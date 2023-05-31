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
	PublicKey    spk // The peer’s public key
	PresharedKey key // The peer's pre-shared key

	Endpoint *net.UDPAddr // The peers's endpoint
}

func (p *PeerConfig) PID() pid {
	return pid(khPeerID.hash(p.PublicKey[:]))
}

type peer struct {
	server *Server

	initialEndpoint *net.UDPAddr // The peers's endpoint as configured
	endpoint        *net.UDPAddr // The peers's endpoint as learned from its last packet

	spkt spk // The peer’s public key
	psk  key // The peer's pre-shared key

	biscuitUsed biscuitNo // The biscuit_no from the last biscuit accepted for the peer as part of InitConf processing

	logger *slog.Logger
}

func (s *Server) newPeer(cfg *PeerConfig) (*peer, error) {
	if cfg.PublicKey == nil {
		return nil, errors.New("missing public key")
	}

	p := &peer{
		server: s,

		initialEndpoint: cfg.Endpoint,
		endpoint:        cfg.Endpoint,
		spkt:            cfg.PublicKey,
		psk:             cfg.PresharedKey,
	}

	p.logger = s.logger.With(slog.Any("pid", p.PID()))

	return p, nil
}

func (p *peer) PID() pid {
	return pid(khPeerID.hash(p.spkt[:]))
}

func (p *peer) Run() error {
	if p.initialEndpoint == nil {
		p.logger.Debug("Skipping peer without endpoint")
		return nil
	}

	hs := &handshake{
		peer:   p,
		server: p.server,
		role:   initiator,
	}

	m, err := hs.sendInitHello()
	if err != nil {
		return err
	}

	if err := hs.send(m); err != nil {
		return fmt.Errorf("failed to send: %w", err)
	}

	p.server.handshakes[hs.sidi] = hs
	p.logger.Debug("Started new handshake", "sidi", hs.sidi)

	return nil
}
