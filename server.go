// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

type Server struct {
	spkm     spk
	sskm     ssk
	handlers []Handler

	biscuitKeys   [2]key
	biscuitCtr    biscuitNo
	biscuitTicker *time.Ticker
	biscuitLock   sync.RWMutex // Protects biscuitCtr and biscuitKeys

	peers          map[pid]*peer               // A lookup table mapping the peer ID to the internal peer structure
	handshakes     map[sid]*initiatorHandshake // A lookup table mapping the session ID to the ongoing initiator handshake or live session
	handshakesLock sync.RWMutex                // Protects handshakes

	conn      Conn
	closeConn bool

	logger *slog.Logger
}

func NewUDPServer(cfg Config) (*Server, error) {
	if len(cfg.ListenAddrs) == 0 {
		// Listen on random port on all interfaces by default
		cfg.ListenAddrs = append(cfg.ListenAddrs, &net.UDPAddr{})
	}

	var err error
	if cfg.Conn, err = NewUDPConn(cfg.ListenAddrs); err != nil {
		return nil, err
	}

	// Server.Close() should also close the connection
	cfg.closeConn = true

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
		handshakes: map[sid]*initiatorHandshake{},

		conn:      cfg.Conn,
		closeConn: cfg.closeConn,

		logger: cfg.Logger,
	}

	if s.logger == nil {
		s.logger = slog.Default()
	}

	recvFncs, err := s.conn.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open listeners: %w", err)
	}

	for _, pCfg := range cfg.Peers {
		pCfg := pCfg

		p, err := s.newPeer(pCfg)
		if err != nil {
			return nil, err
		}

		s.logger.Debug("Added peer", "pid", p.PID())

		s.peers[p.PID()] = p
	}

	for _, recvFnc := range recvFncs {
		go s.receiveLoop(recvFnc)
	}

	go s.biscuitLoop()

	return s, nil
}

func (s *Server) PID() PeerID { //nolint:revive
	return pid(khPeerID.hash(s.spkm[:]))
}

func (s *Server) Close() error {
	s.biscuitTicker.Stop()

	if s.closeConn {
		if err := s.conn.Close(); err != nil {
			return err
		}
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

func (s *Server) receiveLoop(recvFnc ReceiveFunc) {
	for {
		pl, from, err := recvFnc(s.spkm)
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
	oldBiscuitKey := s.biscuitKeys[0]
	s.biscuitKeys = [2]key{
		newBiscuitKey,
		oldBiscuitKey,
	}
	s.biscuitLock.Unlock()

	return nil
}

func (s *Server) handle(pl payload, from Endpoint) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recovered from panic: %v", r)
		}
	}()

	mTyp := msgTypeFromPayload(pl)

	s.logger.Debug("Handling message", "type", mTyp)

	// Get or create handshake state
	switch req := pl.(type) {
	case *initHello:
		hs := &responderHandshake{
			handshake: handshake{
				server: s,
			},
		}

		if err = hs.handleInitHello(req); err != nil {
			return err
		}

		if err = hs.sendRespHello(from); err != nil {
			return err
		}

	case *respHello:
		hs, ok := s.getHandshake(req.sidi)
		if !ok {
			return fmt.Errorf("%s: %s", errSessionNotFound, req.sidi)
		}

		if hs.nextMsg != msgTypeRespHello {
			return fmt.Errorf("%w: %s", errUnexpectedMsgType, mTyp)
		}

		if err = hs.handleRespHello(req); err != nil {
			return err
		}

		hs.txTimer.Stop()

		if err = hs.sendInitConf(); err != nil {
			return err
		}

		hs.nextMsg = msgTypeEmptyData

	case *initConf:
		hs := &responderHandshake{
			handshake: handshake{
				server: s,
			},
		}

		if err = hs.handleInitConf(req); err != nil {
			return err
		}

		if err = hs.sendEmptyData(from); err != nil {
			return err
		}

		s.completeHandshake(&hs.handshake, from, RekeyAfterTimeResponder)

	case *emptyData:
		hs, ok := s.getHandshake(req.sid)
		if !ok {
			return fmt.Errorf("%s: %s", errSessionNotFound, req.sid)
		}

		if hs.nextMsg != msgTypeEmptyData {
			return fmt.Errorf("%w: %s", errUnexpectedMsgType, mTyp)
		}

		if err = hs.handleEmptyData(req); err != nil {
			return err
		}

		hs.nextMsg = msgTypeData
		hs.txTimer.Stop()
		hs.expiryTimer.Stop()

		s.removeHandshake(hs)
		s.completeHandshake(&hs.handshake, from, RekeyAfterTimeInitiator)

	default:
		return errInvalidMsgType
	}

	return nil
}

func (s *Server) getHandshake(sid sid) (*initiatorHandshake, bool) {
	s.handshakesLock.RLock()
	hs, ok := s.handshakes[sid]
	s.handshakesLock.RUnlock()

	return hs, ok
}

func (s *Server) addHandshake(hs *initiatorHandshake) {
	s.handshakesLock.Lock()
	s.handshakes[hs.sidi] = hs
	s.handshakesLock.Unlock()
}

func (s *Server) removeHandshake(hs *initiatorHandshake) {
	s.handshakesLock.Lock()
	delete(s.handshakes, hs.sidi)
	s.handshakesLock.Unlock()
}

func (s *Server) initiateHandshake(p *peer) {
	if hs, err := p.initiateHandshake(); err != nil {
		if errors.Is(err, errMissingEndpoint) {
			p.logger.Debug("Skipping handshake due to missing endpoint")
		} else {
			p.logger.Error("Failed to initiate handshake for peer", slog.Any("error", err))
		}
	} else {
		hs.expiryTimer = time.AfterFunc(RejectAfterTime, func() {
			s.expireHandshake(hs)
		})

		s.addHandshake(hs)
	}
}

func (s *Server) completeHandshake(hs *handshake, ep Endpoint, rekeyAfter time.Duration) {
	hs.peer.logger.Debug("Exchanged key with peer")

	if hs.peer.endpoint == nil || !hs.peer.endpoint.Equal(ep) {
		hs.peer.logger.Debug("Learned new endpoint", slog.Any("endpoint", ep))
		hs.peer.endpoint = ep
	}

	for _, h := range s.handlers {
		if h, ok := h.(HandshakeCompletedHandler); ok {
			go h.HandshakeCompleted(hs.peer.PID(), hs.osk)
		}
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

func (s *Server) expireHandshake(hs *initiatorHandshake) {
	hs.peer.logger.Debug("Erasing outdated key from peer")

	s.removeHandshake(hs)

	for _, h := range s.handlers {
		if h, ok := h.(HandshakeExpiredHandler); ok {
			go h.HandshakeExpired(hs.peer.PID())
		}
	}
}
