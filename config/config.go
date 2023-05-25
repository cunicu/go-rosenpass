// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
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

func (c *PeerSection) FromConfigWithPipes(pc rp.PeerConfig, e *exec.Cmd, h rp.HandshakeHandler) (err error) {
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

	if h != nil {
		pid := pc.PID()
		if ko, err := keyoutReader(func(k rp.Key) {
			h.HandshakeCompleted(pid, k)
		}, e); err != nil {
			return nil
		} else {
			c.KeyOut = &ko
		}
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

	for _, p := range f.Peers {
		if pc, err := p.ToConfig(); err != nil {
			return c, err
		} else {
			c.Peers = append(c.Peers, pc)
		}
	}

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
		if err := ps.FromConfigWithPipes(pc, e, c.Handler); err != nil {
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

func keyoutReader(h func(osk rp.Key), e *exec.Cmd) (string, error) {
	rd, wr, err := os.Pipe()
	if err != nil {
		return "", fmt.Errorf("failed to create pipe: %w", err)
	}

	go func() {
		for {
			buf := make([]byte, 100)

			n, err := rd.Read(buf)
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}

				log.Fatalf("Failed to read key: %s", err)
			}

			var k rp.Key
			if n, err := base64.StdEncoding.Decode(k[:], buf[:n]); err != nil {
				log.Fatalf("Failed to decode key: %s", err)
			} else if n != 32 {
				log.Fatalf("Partial read: %d", n)
			}

			h(k)
		}
	}()

	i := len(e.ExtraFiles) + 3
	e.ExtraFiles = append(e.ExtraFiles, wr)

	return fmt.Sprintf("/dev/fd/%d", i), nil
}

func bufferedReader(c *exec.Cmd) (string, *bytes.Buffer, error) {
	fn, rd, err := pipeReader(c)
	if err != nil {
		return "", nil, err
	}

	buf := &bytes.Buffer{}

	go func() {
		if _, err := io.Copy(buf, rd); err != nil {
			log.Fatalf("Failed to copy: %s", err)
		}
	}()

	return fn, buf, nil
}

func bufferedWriter(c *exec.Cmd, b []byte) (string, error) {
	fn, wr, err := pipeWriter(c)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(b)

	go func() {
		if _, err := io.Copy(wr, buf); err != nil {
			log.Fatalf("Failed to copy: %s", err)
		}
		if err := wr.Close(); err != nil {
			log.Fatalf("Failed to close: %s", err)
		}
	}()

	return fn, nil
}

func pipeReader(c *exec.Cmd) (string, io.Reader, error) {
	rd, wr, err := os.Pipe()
	if err != nil {
		return "", nil, fmt.Errorf("failed to create pipe: %w", err)
	}

	i := len(c.ExtraFiles) + 3
	c.ExtraFiles = append(c.ExtraFiles, wr)

	return fmt.Sprintf("/dev/fd/%d", i), rd, nil
}

func pipeWriter(c *exec.Cmd) (string, io.WriteCloser, error) {
	rd, wr, err := os.Pipe()
	if err != nil {
		return "", nil, fmt.Errorf("failed to create pipe: %w", err)
	}

	i := len(c.ExtraFiles) + 3
	c.ExtraFiles = append(c.ExtraFiles, rd)

	return fmt.Sprintf("/dev/fd/%d", i), wr, nil
}
