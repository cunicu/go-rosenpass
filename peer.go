// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/exp/slog"
)

var ErrMissingEndpoint = errors.New("missing endpoint")

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

	rekeyTimer *time.Timer

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

func PeerIDFromPublicKey(spk spk) pid {
	return pid(khPeerID.hash(spk[:]))
}

func (p *peer) PID() pid {
	return PeerIDFromPublicKey(p.spkt)
}

func (p *peer) initiateHandshake() (*initiatorHandshake, error) {
	if p.endpoint == nil {
		return nil, ErrMissingEndpoint
	}

	hs := &initiatorHandshake{
		handshake: handshake{
			peer:   p,
			server: p.server,
		},
	}

	m, err := hs.sendInitHello()
	if err != nil {
		return nil, err
	}

	if err := hs.send(m); err != nil {
		return nil, fmt.Errorf("failed to send: %w", err)
	}

	p.logger.Debug("Started new handshake", "sidi", hs.sidi)

	return hs, nil
}
