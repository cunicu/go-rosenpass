// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
	rp "github.com/stv0g/go-rosenpass"
	"golang.org/x/exp/slog"
)

type File struct {
	PublicKey string `toml:"public_key"`
	SecretKey string `toml:"secret_key"`

	Listen    []string `toml:"listen,omitempty"`
	Verbosity string   `toml:"verbosity,omitempty"`

	Peers []PeerSection `toml:"peers,omitempty"`
}

func (c *File) Load(r io.Reader) error {
	enc := toml.NewDecoder(r)
	return enc.Decode(c)
}

func (f *File) Dump(w io.Writer) error {
	enc := toml.NewEncoder(w)
	return enc.Encode(f)
}

func (f *File) LoadFile(fn string) error {
	fh, err := os.Open(fn)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	if err := f.Load(fh); err != nil {
		return err
	}

	if err := fh.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	return nil
}

func (f *File) DumpFile(fn string) error {
	fh, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	if err := f.Dump(fh); err != nil {
		return err
	}

	if err := fh.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	return nil
}

func (f *File) ToConfig() (c rp.Config, err error) {
	for _, las := range f.Listen {
		if c.Listen, err = net.ResolveUDPAddr("udp", las); err != nil {
			return c, fmt.Errorf("failed to resolve listen address: %w", err)
		}

		if len(f.Listen) > 1 {
			slog.Warn("Only first listen address is used!")
			break
		}
	}

	if c.PublicKey, err = os.ReadFile(f.PublicKey); err != nil {
		return c, fmt.Errorf("failed to read public key: %w", err)
	}

	if c.SecretKey, err = os.ReadFile(f.SecretKey); err != nil {
		return c, fmt.Errorf("failed to read public key: %w", err)
	}

	ch := &exchangeCommandHandler{
		peers: map[rp.PeerID][]string{},
	}
	kh := &keyoutFileHandler{
		peers: map[rp.PeerID]string{},
	}

	for _, p := range f.Peers {
		if pc, err := p.ToConfig(); err != nil {
			return c, err
		} else {
			c.Peers = append(c.Peers, pc)

			pid := pc.PID()

			// Register peer to handlers
			if p.KeyOut != nil {
				if err := kh.addPeerKeyoutFile(pid, *p.KeyOut); err != nil {
					return c, fmt.Errorf("failed to add keyout file: %w", err)
				}
			}

			if p.ExchangeCommand != nil {
				ch.addPeerCommand(pid, p.ExchangeCommand)
			}
		}
	}

	c.Handlers = append(c.Handlers, kh)

	return c, nil
}

func (f *File) FromConfig(c rp.Config, dir string) (err error) {
	f.Verbosity = "Verbose" // TODO: Make configurable

	if c.Listen != nil {
		f.Listen = []string{
			c.Listen.String(),
		}
	}

	f.PublicKey = filepath.Join(dir, "public.key")
	if err := os.WriteFile(f.PublicKey, c.PublicKey, 0o644); err != nil {
		return err
	}

	f.SecretKey = filepath.Join(dir, "secret.key")
	if err := os.WriteFile(f.SecretKey, c.SecretKey, 0o600); err != nil {
		return err
	}

	for i, pc := range c.Peers {
		pDir := filepath.Join(dir, fmt.Sprintf("peer%d", i))
		if err := os.MkdirAll(pDir, 0o755); err != nil {
			return err
		}

		var ps PeerSection
		if err := ps.FromConfig(pc, pDir, c.Handlers); err != nil {
			return err
		} else {
			f.Peers = append(f.Peers, ps)
		}
	}

	return nil
}
