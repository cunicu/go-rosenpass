// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	rp "cunicu.li/go-rosenpass"
	"cunicu.li/go-rosenpass/handlers"

	"github.com/pelletier/go-toml/v2"
)

type File struct {
	// A filename containing this nodes raw public key
	PublicKey string `toml:"public_key" comment:"A filename containing this nodes raw public key"`

	// A filename containing this nodes raw secret key
	SecretKey string `toml:"secret_key" comment:"A filename containing this nodes raw secret key"`

	// A host:port pair to identify the interface and port to listen for handshake messages
	ListenAddrs []string `toml:"listen,omitempty" comment:"A host:port pair to identify the interface and port to listen for handshake messages"`

	// Use eBPF to listen and share the same port with an existing WireGuard interface
	ListenSinglePort bool `toml:"single_port,omitempty"`

	// Set to 'Verbose' or 'Quiet'
	Verbosity string `toml:"verbosity,omitempty" comment:"Set to 'Verbose' or 'Quiet'"`

	// A table of peers
	Peers []PeerSection `toml:"peers,omitempty" comment:"A table of peers"`
}

func (f *File) Load(r io.Reader) error {
	enc := toml.NewDecoder(r)
	return enc.Decode(f)
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
	c.ListenSinglePort = f.ListenSinglePort

	for _, las := range f.ListenAddrs {
		addr, err := net.ResolveUDPAddr("udp", las)
		if err != nil {
			return c, fmt.Errorf("failed to resolve listen address: %w", err)
		}

		c.ListenAddrs = append(c.ListenAddrs, addr)
	}

	if c.PublicKey, err = os.ReadFile(f.PublicKey); err != nil {
		return c, fmt.Errorf("failed to read public key: %w", err)
	}

	if c.SecretKey, err = os.ReadFile(f.SecretKey); err != nil {
		return c, fmt.Errorf("failed to read public key: %w", err)
	}

	ch := handlers.NewExchangeCommandHandler()
	kh := handlers.NewkeyoutHandler()
	wh, err := handlers.NewWireGuardHandler()
	if err != nil {
		return c, fmt.Errorf("failed to configure WireGuard interfaces: %w", err)
	}

	c.Handlers = append(c.Handlers, kh, ch, wh)

	for _, p := range f.Peers {
		pc, err := p.ToConfig()
		if err != nil {
			return c, err
		}

		c.Peers = append(c.Peers, pc)

		pid := pc.PID()

		// Register peer to handlers
		if p.KeyOut != nil {
			if err := kh.AddPeer(pid, *p.KeyOut); err != nil {
				return c, fmt.Errorf("failed to add keyout file: %w", err)
			}
		}

		if p.ExchangeCommand != nil {
			ch.AddPeer(pid, p.ExchangeCommand)
		}

		if p.WireGuard != nil {
			wh.AddPeer(pid, p.WireGuard.Interface, p.WireGuard.PublicKey)
		}
	}

	return c, nil
}

func (f *File) FromConfig(c rp.Config, dir string) (err error) {
	f.Verbosity = "Verbose" // TODO: Make configurable

	if c.ListenAddrs != nil {
		for _, la := range c.ListenAddrs {
			f.ListenAddrs = append(f.ListenAddrs, la.String())
		}
	}

	f.PublicKey = filepath.Join(dir, "public.key")
	if err := os.WriteFile(f.PublicKey, c.PublicKey, 0o600); err != nil {
		return err
	}

	f.SecretKey = filepath.Join(dir, "secret.key")
	if err := os.WriteFile(f.SecretKey, c.SecretKey, 0o600); err != nil {
		return err
	}

	for i, pc := range c.Peers {
		pDir := filepath.Join(dir, fmt.Sprintf("peer%d", i)) // nolint:forbidigo
		if err := os.MkdirAll(pDir, 0o755); err != nil {
			return err
		}

		var ps PeerSection
		if err := ps.FromConfig(pc, pDir); err != nil {
			return err
		}

		f.Peers = append(f.Peers, ps)
	}

	return nil
}
