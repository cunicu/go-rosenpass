// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"
)

type HandshakeHandler interface {
	HandshakeCompleted(pid, key)
}

type Server struct {
	spkm     spk
	sskm     ssk
	handlers []HandshakeHandler

	biscuitKeys []key
	biscuitCtr  biscuitNo

	peers      map[pid]*peer      // A lookup table mapping the peer ID to the internal peer structure
	handshakes map[sid]*handshake // A lookup table mapping the session ID to the ongoing initiator handshake or live session

	conn   conn
	logger *slog.Logger
}

func NewUDPServer(cfg Config) (*Server, error) {
	if cfg.Listen != nil {
		var err error
		if cfg.Conn, err = newUDPConn(cfg.Listen); err != nil {
			return nil, err
		}
	}

	return NewServer(cfg)
}

func NewServer(cfg Config) (*Server, error) {
	s := &Server{
		spkm:     cfg.PublicKey,
		sskm:     cfg.SecretKey,
		handlers: cfg.Handlers,

		biscuitKeys: []key{},

		peers:      map[pid]*peer{},
		handshakes: map[sid]*handshake{},
		conn:       cfg.Conn,

		logger: cfg.Logger,
	}

	if s.logger == nil {
		s.logger = slog.Default()
	}

	biscuitKey, err := generateKey(keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate biscuit key: %w", err)
	}

	s.biscuitKeys = []key{
		key(biscuitKey),
	}

	for _, pCfg := range cfg.Peers {
		p, err := s.newPeer(&pCfg)
		if err != nil {
			return nil, err
		}

		s.logger.Debug("Added peer", "pid", p.PID())

		s.peers[p.PID()] = p
	}

	go s.receiveLoop()

	return s, nil
}

func (s *Server) PID() pid {
	return pid(khPeerID.hash(s.spkm[:]))
}

func (s *Server) Close() error {
	if s.conn != nil {
		if err := s.conn.Close(); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) Run() error {
	g := &errgroup.Group{}

	for _, p := range s.peers {
		g.Go(p.Run)
	}

	return g.Wait()
}

func (s *Server) receiveLoop() {
	for {
		pl, from, err := s.conn.Receive(s.spkm)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				s.logger.Error("Connection closed")
				return
			}

			s.logger.Error("Failed to receive message", "error", err)
			continue
		}

		if err := s.handle(pl, from); err != nil {
			s.logger.Error("Failed to handle message", "error", err)
			continue
		}
	}
}

func (s *Server) handle(pl payload, from *net.UDPAddr) error {
	var resp payload
	var hs *handshake
	var ok bool
	var err error

	mTyp := msgTypeFromPayload(pl)

	s.logger.Debug("Handling message", "type", mTyp)

	// Get or create handshake state
	switch req := pl.(type) {
	case *initHello, *initConf:
		hs = &handshake{
			server:  s,
			nextMsg: mTyp,
			role:    responder,
		}

	case *respHello:
		if hs, ok = s.handshakes[req.sidi]; !ok {
			return fmt.Errorf("%s: %s", ErrSessionNotFound, req.sidi)
		}

	case *emptyData:
		if hs, ok = s.handshakes[req.sid]; !ok {
			return fmt.Errorf("%s: %s", ErrSessionNotFound, req.sid)
		}

	default:
		return ErrInvalidMsgType
	}

	if hs.nextMsg != mTyp {
		return fmt.Errorf("%w: %s", ErrUnexpectedMsgType, mTyp)
	}

	// Handle message
	switch req := pl.(type) {
	case *initHello:
		if err = hs.handleInitHello(req); err != nil {
			return err
		}

		// Update peers endpoint of the init hello message
		// has been received from an unknown address.
		if hs.peer.endpoint == nil || !compareAddr(hs.peer.endpoint, from) {
			hs.peer.endpoint = from
			hs.peer.logger.Debug("Learned new endpoint", slog.Any("endpoint", from))
		}

		if resp, err = hs.sendRespHello(); err != nil {
			return err
		}

	case *respHello:
		if err = hs.handleRespHello(req); err != nil {
			return err
		}

		if resp, err = hs.sendInitConf(); err != nil {
			return err
		}

		hs.nextMsg = msgTypeEmptyData

	case *initConf:
		if err = hs.handleInitConf(req); err != nil {
			return err
		}

		if resp, err = hs.sendEmptyData(); err != nil {
			return err
		}

	case *emptyData:
		if err = hs.handleEmptyData(req); err != nil {
			return err
		}

	default:
		return ErrInvalidMsgType
	}

	// Send response
	if resp == nil {
		return nil
	}

	if hs.peer == nil {
		return fmt.Errorf("missing peer?")
	}

	return hs.send(resp)
}
