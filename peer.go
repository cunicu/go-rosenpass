// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/exp/slog"
)

type PeerConfig struct {
	Endpoint     *net.UDPAddr // The peers's endpoint
	PublicKey    spk          // The peer’s public key
	PresharedKey psk          // The peer's pre-shared key
}

type peer struct {
	server *Server

	ep   *net.UDPAddr // The peers's endpoint
	spkt spk          // The peer’s public key
	psk  psk          // The peer's pre-shared key

	biscuitUsed biscuitNo // The biscuit_no from the last biscuit accepted for the peer as part of InitConf processing

	logger *slog.Logger
}

func (s *Server) newPeer(cfg *PeerConfig) (*peer, error) {
	if cfg.PublicKey == nil {
		return nil, errors.New("missing public key")
	}

	p := &peer{
		server: s,

		ep:   cfg.Endpoint,
		spkt: cfg.PublicKey,
	}

	p.logger = s.logger.With(slog.Any("pid", p.PID()))

	return p, nil
}

func (p *peer) PID() pid {
	return lhash(lblPeerID, p.spkt[:])
}

func (p *peer) Run() error {
	if p.ep == nil {
		p.logger.Debug("Skipping peer without endpoint")
		return nil
	}

	hs := &handshake{
		peer:   p,
		server: p.server,
	}

	m, err := hs.sendInitHello()
	if err != nil {
		return err
	}

	if err := p.server.send(m, p); err != nil {
		return fmt.Errorf("failed to send: %w", err)
	}

	return nil
}
