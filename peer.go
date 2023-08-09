// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"
)

var (
	errMissingEndpoint  = errors.New("missing endpoint")
	errMissingPublicKey = errors.New("missing public key")
)

type PeerConfig struct {
	PublicKey    spk // The peer’s public key
	PresharedKey key // The peer's pre-shared key

	Endpoint *net.UDPAddr // The peers's endpoint
}

func (p *PeerConfig) PID() PeerID { //nolint:revive
	return pid(khPeerID.hash(p.PublicKey[:]))
}

type peer struct {
	server *Server

	rekeyTimer *time.Timer

	initialEndpoint endpoint // The peers's endpoint as configured
	endpoint        endpoint // The peers's endpoint as learned from its last packet

	spkt spk // The peer’s public key
	psk  key // The peer's pre-shared key

	biscuitUsed biscuitNo // The biscuit_no from the last biscuit accepted for the peer as part of InitConf processing

	logger *slog.Logger
}

func (s *Server) newPeer(cfg PeerConfig) (*peer, error) {
	if cfg.PublicKey == nil {
		return nil, errMissingPublicKey
	}

	p := &peer{
		server: s,

		initialEndpoint: &udpEndpoint{cfg.Endpoint},
		spkt:            cfg.PublicKey,
		psk:             cfg.PresharedKey,
	}

	if cfg.Endpoint != nil {
		p.endpoint = &udpEndpoint{cfg.Endpoint}
	}

	p.logger = s.logger.With(slog.Any("pid", p.PID()))

	return p, nil
}

func PeerIDFromPublicKey(spk spk) PeerID { //nolint:revive
	return pid(khPeerID.hash(spk[:]))
}

func (p *peer) PID() pid {
	return PeerIDFromPublicKey(p.spkt)
}

func (p *peer) initiateHandshake() (*initiatorHandshake, error) {
	if p.endpoint == nil {
		return nil, errMissingEndpoint
	}

	hs := &initiatorHandshake{
		handshake: handshake{
			peer:   p,
			server: p.server,
		},
	}

	if err := hs.sendInitHello(); err != nil {
		return nil, fmt.Errorf("failed to send: %w", err)
	}

	p.logger.Debug("Started new handshake", "sidi", hs.sidi)

	return hs, nil
}
