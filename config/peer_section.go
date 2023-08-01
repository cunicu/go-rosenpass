// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/stv0g/go-rosenpass"
	rp "github.com/stv0g/go-rosenpass"
)

type WireGuardSection struct {
	// The peers network interface name
	Interface string `toml:"interface"`

	// The peers WireGuard (not Rosenpass') PublicKey
	PublicKey rp.Key `toml:"public_key"`
}

type PeerSection struct {
	// The peer’s public key
	PublicKey string `toml:"public_key" comment:"The peer’s public key"`

	// The peers's endpoint
	Endpoint *string `toml:"endpoint" comment:"The peers's endpoint"`

	// The peer's pre-shared key
	PresharedKey *string `toml:"pre_shared_key" comment:"The peer's pre-shared key"`

	// A path to a file to which we will write the base64-encoded PSK after each handshake
	KeyOut *string `toml:"key_out" comment:"A path to a file to which we will write the base64-encoded PSK after each handshake"`

	// A command which is executed after each completed handshake
	ExchangeCommand []string `toml:"exchange_command,multiline,omitempty" comment:"A command which is executed after each completed handshake"`

	// Settings for directly configuring a WireGuard peer with the negotiated PSK
	WireGuard *WireGuardSection `toml:"wireguard,inline" comment:"Settings for directly configuring a WireGuard peer with the negotiated PSK"`
}

func (ps *PeerSection) ToConfig() (pc rosenpass.PeerConfig, err error) {
	if pc.PublicKey, err = os.ReadFile(ps.PublicKey); err != nil {
		return pc, fmt.Errorf("failed to read public key: %w", err)
	}

	if ps.PresharedKey != nil {
		k, err := os.ReadFile(*ps.PresharedKey)
		if err != nil {
			return pc, fmt.Errorf("failed to read public key: %w", err)
		}

		if err := pc.PresharedKey.UnmarshalText(k); err != nil {
			return pc, fmt.Errorf("failed to parse preshared key: %w", err)
		}
	}

	if ps.Endpoint != nil {
		if pc.Endpoint, err = net.ResolveUDPAddr("udp", *ps.Endpoint); err != nil {
			return pc, fmt.Errorf("failed to resolve listen address: %w", err)
		}
	}

	return pc, err
}

func (ps *PeerSection) FromConfig(pc rp.PeerConfig, dir string) (err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create dir: %w", err)
	}

	if pc.Endpoint != nil {
		ep := pc.Endpoint.String()
		ps.Endpoint = &ep
	}

	keyOutFile := filepath.Join(dir, "out.key")
	ps.KeyOut = &keyOutFile

	ps.PublicKey = filepath.Join(dir, "public.key")
	if err := os.WriteFile(ps.PublicKey, pc.PublicKey, 0o600); err != nil {
		return err
	}

	zeroKey := rp.PresharedKey{}
	if pc.PresharedKey != zeroKey {
		presharedKey := filepath.Join(dir, "preshared.key")
		if err := os.WriteFile(presharedKey, []byte(base64.StdEncoding.EncodeToString(pc.PresharedKey[:])), 0o600); err != nil {
			return err
		}
		ps.PresharedKey = &presharedKey
	}

	return nil
}
