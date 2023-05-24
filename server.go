// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"fmt"
	"net"

	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"
)

type HandshakeHandler interface {
	HandshakeCompleted(pid, key)
	HandshakeFailed(pid, error)
}

type ServerConfig struct {
	Listen  *net.UDPAddr
	Handler HandshakeHandler // TODO: Use any? for API extensibility?

	PublicKey  spk
	PrivateKey ssk

	Peers []PeerConfig

	Logger *slog.Logger
}

type Server struct {
	spkm    spk
	sskm    ssk
	handler HandshakeHandler

	biscuitKeys []key
	biscuitCtr  biscuitNo

	peers      map[pid]*peer      // A lookup table mapping the peer ID to the internal peer structure
	handshakes map[sid]*handshake // A lookup table mapping the session ID to the ongoing initiator handshake or live session

	conn *net.UDPConn

	logger *slog.Logger
}

func NewServer(cfg *ServerConfig) (*Server, error) {
	s := &Server{
		spkm:    cfg.PublicKey,
		sskm:    cfg.PrivateKey,
		handler: cfg.Handler,

		biscuitKeys: []key{},

		peers: map[pid]*peer{},

		logger: cfg.Logger,
	}

	if s.logger == nil {
		s.logger = slog.Default()
	}

	if cfg.Listen != nil {
		var err error
		s.conn, err = net.ListenUDP("udp", cfg.Listen)
		if err != nil {
			return nil, fmt.Errorf("failed to listen: %w", err)
		}

		go s.readLoop()
	}

	for _, pcfg := range cfg.Peers {
		p, err := s.newPeer(&pcfg)
		if err != nil {
			return nil, err
		}

		s.peers[p.PID()] = p
	}

	return s, nil
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

func (s *Server) readLoop() {
	// TODO: Check for appropriate MTU
	buf := make([]byte, 1500)

	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			s.logger.Error("Failed to read", err)
		}

		s.logger.Debug("Received", slog.Int("len", n), slog.Any("data", buf), slog.Any("from", from))

		e := &envelope{}
		if m, err := e.UnmarshalBinary(buf); err != nil {
			s.logger.Error("Received malformed packet", err)
			continue
		} else if m != n {
			s.logger.Error("Parsed partial packet")
			continue
		}

		if err := s.handleEnvelope(e); err != nil {
			s.logger.Error("Failed to handle message", err)
		}
	}
}

func (s *Server) send(pl payload, p *peer) error {
	e := envelope{
		payload: pl,
	}

	switch pl.(type) {
	case *initHello:
		e.typ = msgTypeInitHello
	case *respHello:
		e.typ = msgTypeRespHello
	case *initConf:
		e.typ = msgTypeInitConf
	case *emptyData:
		e.typ = msgTypeEmptyData
	}

	buf, err := e.MarshalBinary()
	if err != nil {
		return err
	}

	if n, err := s.conn.WriteToUDP(buf, p.ep); err != nil {
		return err
	} else if n != len(buf) {
		return fmt.Errorf("partial write")
	}

	return nil
}

func (s *Server) handleEnvelope(e *envelope) error {
	var err error
	var resp payload
	var hs *handshake
	var ok bool

	// Get or create handshake state
	switch req := e.payload.(type) {
	case *initHello, *initConf:
		hs = &handshake{
			server:  s,
			nextMsg: e.typ,
		}
	case *respHello:
		if hs, ok = s.handshakes[req.sidi]; !ok {
			return ErrSessionNotFound
		}
	case *emptyData:
		if hs, ok = s.handshakes[req.sid]; !ok {
			return ErrSessionNotFound
		}
	default:
		return ErrInvalidMsgType
	}

	if hs.nextMsg != e.typ {
		return fmt.Errorf("%w: %s", ErrUnexpectedMsgType, e.typ)
	}

	// Handle message
	switch req := e.payload.(type) {
	case *initHello:
		if err = hs.handleInitHello(req); err != nil {
			return err
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
	}

	// Send response
	if resp != nil {
	}

	return nil
}
