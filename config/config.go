// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"github.com/pelletier/go-toml/v2"
	"github.com/stv0g/go-rosenpass"
	rp "github.com/stv0g/go-rosenpass"
	"golang.org/x/exp/slog"
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
	fh, err := os.OpenFile(fn, os.O_WRONLY|os.O_TRUNC, 0o644)
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

func (f *PeerSection) ToConfig() (pc rosenpass.PeerConfig, err error) {
	if pc.PublicKey, err = os.ReadFile(f.PublicKey); err != nil {
		return pc, fmt.Errorf("failed to read public key: %w", err)
	}

	if f.PresharedKey != nil {
		if k, err := os.ReadFile(*f.PresharedKey); err != nil {
			return pc, fmt.Errorf("failed to read public key: %w", err)
		} else {
			pc.PresharedKey = rp.PresharedKey(k)
		}
	}

	if f.Endpoint != nil {
		if pc.Endpoint, err = net.ResolveUDPAddr("udp", *f.Endpoint); err != nil {
			return pc, fmt.Errorf("failed to resolve listen address: %w", err)
		}
	}

	return pc, err
}

func (c *PeerSection) FromConfigWithPipes(pc rp.PeerConfig, e *exec.Cmd, hs []rp.HandshakeHandler) (err error) {
	if pc.Endpoint != nil {
		ep := pc.Endpoint.String()
		c.Endpoint = &ep
	}

	if c.PublicKey, err = bufferedWriter(e, pc.PublicKey); err != nil {
		return err
	}

	if psk, err := bufferedWriter(e, pc.PresharedKey[:]); err != nil {
		return err
	} else {
		c.PresharedKey = &psk
	}

	pid := pc.PID()
	if ko, err := keyoutReader(func(k rp.Key) {
		for _, h := range hs {
			h.HandshakeCompleted(pid, k)
		}
	}, e); err != nil {
		return nil
	} else {
		c.KeyOut = &ko
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
		peers: map[rp.PeerID]io.Writer{},
	}

	for _, p := range f.Peers {
		if pc, err := p.ToConfig(); err != nil {
			return c, err
		} else {
			c.Peers = append(c.Peers, pc)

			pid := pc.PID()

			// Register peer to handlers
			if p.KeyOut != nil {
				kh.addPeerKeyoutFile(pid, *p.KeyOut)
			}

			if p.ExchangeCommand != nil {
				ch.addPeerCommand(pid, p.ExchangeCommand)
			}
		}
	}

	c.Handlers = append(c.Handlers, kh)

	return c, nil
}

func (f *File) FromConfigWithPipes(c rp.Config, e *exec.Cmd) (err error) {
	f.Verbosity = "Verbose" // TODO: Make configurable

	if c.Listen != nil {
		f.Listen = []string{
			c.Listen.String(),
		}
	}

	if f.PublicKey, err = bufferedWriter(e, c.PublicKey); err != nil {
		return err
	}

	if f.SecretKey, err = bufferedWriter(e, c.SecretKey); err != nil {
		return err
	}

	for _, pc := range c.Peers {
		var ps PeerSection
		if err := ps.FromConfigWithPipes(pc, e, c.Handlers); err != nil {
			return err
		} else {
			f.Peers = append(f.Peers, ps)
		}
	}

	return nil
}

func NewConfigPipe(c rp.Config, e *exec.Cmd) (string, error) {
	var f File
	if err := f.FromConfigWithPipes(c, e); err != nil {
		return "", err
	}

	fn, wr, err := pipeWriter(e)
	if err != nil {
		return "", err
	}

	go func() {
		f.Dump(wr)
		wr.Close()
	}()

	return fn, nil
}
