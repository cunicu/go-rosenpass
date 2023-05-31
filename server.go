// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/exp/slog"
)

type Server struct {
	spkm     spk
	sskm     ssk
	handlers []Handler

	biscuitKeys   [2]key
	biscuitCtr    biscuitNo
	biscuitTicker *time.Ticker
	biscuitLock   sync.RWMutex // Protects biscuitCtr and biscuitKeys

	peers          map[pid]*peer      // A lookup table mapping the peer ID to the internal peer structure
	handshakes     map[sid]*handshake // A lookup table mapping the session ID to the ongoing initiator handshake or live session
	handshakesLock sync.RWMutex       // Protects handshakes

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
	biscuitKey, err := generateKey(keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate biscuit key: %w", err)
	}

	s := &Server{
		spkm:     cfg.PublicKey,
		sskm:     cfg.SecretKey,
		handlers: cfg.Handlers,

		biscuitKeys: [2]key{
			key(biscuitKey),
		},
		biscuitTicker: time.NewTicker(BiscuitEpoch),

		peers:      map[pid]*peer{},
		handshakes: map[sid]*handshake{},
		conn:       cfg.Conn,

		logger: cfg.Logger,
	}

	if s.logger == nil {
		s.logger = slog.Default()
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
	go s.biscuitLoop()

	return s, nil
}

func (s *Server) PID() pid {
	return pid(khPeerID.hash(s.spkm[:]))
}

func (s *Server) Close() error {
	s.biscuitTicker.Stop()

	if err := s.conn.Close(); err != nil {
		return err
	}

	// s.handshakesLock.Lock()

	// for _, hs := range s.handshakes {
	// 	if err := hs.Close(); err != nil {
	// 		return err
	// 	}
	// }

	return nil
}

func (s *Server) Run() error {
	for _, p := range s.peers {
		s.initiateHandshake(p)
	}

	return nil
}

func (s *Server) receiveLoop() {
	for {
		pl, from, err := s.conn.Receive(s.spkm)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
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

func (s *Server) biscuitLoop() {
	for range s.biscuitTicker.C {
		if err := s.rotateBiscuitKey(); err != nil {
			s.logger.Error("Failed to generate biscuit key", slog.Any("error", err))
		}
	}
}

func (s *Server) rotateBiscuitKey() error {
	s.logger.Debug("Renewing biscuit key")

	newBiscuitKey, err := generateBiscuitKey()
	if err != nil {
		return err
	}

	s.biscuitLock.Lock()
	defer s.biscuitLock.Unlock()

	oldBiscuitKey := s.biscuitKeys[0]

	s.biscuitKeys = [2]key{
		newBiscuitKey,
		oldBiscuitKey,
	}

	return nil
}

func (s *Server) handle(pl payload, from *net.UDPAddr) error {
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
		s.handshakesLock.RLock()
		hs, ok = s.handshakes[req.sidi]
		s.handshakesLock.RUnlock()
		if !ok {
			return fmt.Errorf("%s: %s", ErrSessionNotFound, req.sidi)
		}

	case *emptyData:
		s.handshakesLock.RLock()
		hs, ok = s.handshakes[req.sid]
		s.handshakesLock.RUnlock()
		if !ok {
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

		if err = hs.sendRespHello(); err != nil {
			return err
		}

		hs.nextMsg = msgTypeInitConf

	case *respHello:
		if err = hs.handleRespHello(req); err != nil {
			return err
		}

		hs.txTimer.Stop()

		if err = hs.sendInitConf(); err != nil {
			return err
		}

		hs.nextMsg = msgTypeEmptyData

	case *initConf:
		if err = hs.handleInitConf(req); err != nil {
			return err
		}

		if err = hs.sendEmptyData(); err != nil {
			return err
		}

		hs.nextMsg = msgTypeData
		s.completeHandshake(hs)

	case *emptyData:
		if err = hs.handleEmptyData(req); err != nil {
			return err
		}

		hs.nextMsg = msgTypeData
		hs.txTimer.Stop()
		s.completeHandshake(hs)

	default:
		return ErrInvalidMsgType
	}

	return nil
}

func (s *Server) initiateHandshake(p *peer) {
	if hs, err := p.initiateHandshake(); err != nil {
		if errors.Is(err, ErrMissingEndpoint) {
			p.logger.Debug("Skipping handshake due to missing endpoint")
		} else {
			p.logger.Error("Failed to initiate handshake for peer", slog.Any("error", err))
		}
	} else {
		hs.expiryTimer = time.AfterFunc(RejectAfterTime, func() {
			s.expireHandshake(hs)
		})

		s.handshakesLock.Lock()
		s.handshakes[hs.sidi] = hs
		s.handshakesLock.Unlock()
	}
}

func (s *Server) completeHandshake(hs *handshake) {
	hs.peer.logger.Debug("Handshake completed")

	for _, h := range hs.server.handlers {
		if h, ok := h.(HandshakeCompletedHandler); ok {
			h.HandshakeCompleted(hs.peer.PID(), hs.osk)
		}
	}

	var rekeyAfter time.Duration
	if hs.role == initiator {
		hs.expiryTimer.Stop()

		s.handshakesLock.Lock()
		delete(s.handshakes, hs.sidi)
		s.handshakesLock.Unlock()

		rekeyAfter = RekeyAfterTimeInitiator
	} else {
		rekeyAfter = RekeyAfterTimeResponder
	}

	hs.peer.logger.Debug("Rekey", slog.Duration("after", rekeyAfter))

	p := hs.peer

	if p.rekeyTimer != nil {
		p.rekeyTimer.Stop()
	}

	p.rekeyTimer = time.AfterFunc(rekeyAfter, func() {
		s.initiateHandshake(p)
	})
}

func (s *Server) expireHandshake(hs *handshake) {
	hs.peer.logger.Debug("Handshake expired")

	if hs.role == initiator {
		s.handshakesLock.Lock()
		delete(s.handshakes, hs.sidi)
		s.handshakesLock.Unlock()
	}

	for _, h := range hs.server.handlers {
		if h, ok := h.(HandshakeExpiredHandler); ok {
			h.HandshakeExpired(hs.peer.PID())
		}
	}
}