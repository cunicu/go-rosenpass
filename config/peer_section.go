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

func (f *PeerSection) ToConfig() (pc rosenpass.PeerConfig, err error) {
	if pc.PublicKey, err = os.ReadFile(f.PublicKey); err != nil {
		return pc, fmt.Errorf("failed to read public key: %w", err)
	}

	if f.PresharedKey != nil {
		if k, err := os.ReadFile(*f.PresharedKey); err != nil {
			return pc, fmt.Errorf("failed to read public key: %w", err)
		} else {
			if err := pc.PresharedKey.UnmarshalText(k); err != nil {
				return pc, fmt.Errorf("failed to parse preshared key: %w", err)
			}
		}
	}

	if f.Endpoint != nil {
		if pc.Endpoint, err = net.ResolveUDPAddr("udp", *f.Endpoint); err != nil {
			return pc, fmt.Errorf("failed to resolve listen address: %w", err)
		}
	}

	return pc, err
}

func (c *PeerSection) FromConfig(pc rp.PeerConfig, dir string) (err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create dir: %w", err)
	}

	if pc.Endpoint != nil {
		ep := pc.Endpoint.String()
		c.Endpoint = &ep
	}

	keyOutFile := filepath.Join(dir, "out.key")
	c.KeyOut = &keyOutFile

	c.PublicKey = filepath.Join(dir, "public.key")
	if err := os.WriteFile(c.PublicKey, pc.PublicKey, 0o644); err != nil {
		return err
	}

	zeroKey := rp.PresharedKey{}
	if pc.PresharedKey != zeroKey {
		presharedKey := filepath.Join(dir, "preshared.key")
		if err := os.WriteFile(presharedKey, []byte(base64.StdEncoding.EncodeToString(pc.PresharedKey[:])), 0o644); err != nil {
			return err
		}
		c.PresharedKey = &presharedKey
	}

	return nil
}
