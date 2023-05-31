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

type PeerSection struct {
	// The peer’s public key
	PublicKey string `toml:"public_key"`

	// The peers's endpoint
	Endpoint *string `toml:"endpoint"`

	// The peer's pre-shared key
	PresharedKey *string `toml:"pre_shared_key"`

	KeyOut *string `toml:"key_out"`

	ExchangeCommand []string `toml:"exchange_command,multiline,omitempty"`
}

func (f *PeerSection) ToConfig() (pc rosenpass.PeerConfig, err error) {
	if pc.PublicKey, err = os.ReadFile(f.PublicKey); err != nil {
		return pc, fmt.Errorf("failed to read public key: %w", err)
	}

	if f.PresharedKey != nil {
		if k, err := os.ReadFile(*f.PresharedKey); err != nil {
			return pc, fmt.Errorf("failed to read public key: %w", err)
		} else {
			if psk, err := base64.StdEncoding.DecodeString(string(k)); err != nil {
				return pc, fmt.Errorf("failed to parse preshared key: %w", err)
			} else {
				pc.PresharedKey = rp.Key(psk)
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

func (c *PeerSection) FromConfig(pc rp.PeerConfig, dir string, handlers []rp.HandshakeHandler) (err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create dir: %w", err)
	}

	if pc.Endpoint != nil {
		ep := pc.Endpoint.String()
		c.Endpoint = &ep
	}

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

	if len(handlers) > 0 {
		keyout := filepath.Join(dir, "osk.key")
		c.KeyOut = &keyout

		if _, err := keyoutWatcher(keyout, func(osk rp.Key) {
			for _, h := range handlers {
				h.HandshakeCompleted(pc.PID(), osk)
			}
		}); err != nil {
			return err
		}
	}

	return nil
}
