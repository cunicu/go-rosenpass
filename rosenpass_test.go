// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass_test

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
	"strings"
)

const rosenpassExecutable = "rosenpass"

type Peer struct {
	Name string

	PublicKey    []byte
	Endpoint     *net.UDPAddr
	PresharedKey []byte

	Keys chan []byte

	WireGuardDev         string
	WireGuardPeer        []byte
	WireGuardExtraParams []string
}

type Rosenpass struct {
	Name string

	privateKey []byte
	publicKey  []byte

	Verbose    bool
	ListenAddr *net.UDPAddr
	Peers      []*Peer
}

func (rp *Rosenpass) Peer() *Peer {
	return &Peer{
		Name:      rp.Name,
		PublicKey: rp.publicKey,
		Endpoint:  rp.ListenAddr,
	}
}

func (rp *Rosenpass) LoadKeypair(skPath, pkPath string) error {
	var err error

	rp.privateKey, err = os.ReadFile(skPath)
	if err != nil {
		return fmt.Errorf("failed to load public key")
	}

	rp.publicKey, err = os.ReadFile(pkPath)
	if err != nil {
		return fmt.Errorf("failed to load public key")
	}

	return nil
}

func (rp *Rosenpass) SaveKeypair(skPath, pkPath string) error {
	var err error

	if err = os.WriteFile(skPath, rp.privateKey, 0o600); err != nil {
		return fmt.Errorf("failed to load public key")
	}

	if err = os.WriteFile(pkPath, rp.publicKey, 0o644); err != nil {
		return fmt.Errorf("failed to load public key")
	}

	return nil
}

func (rp *Rosenpass) Keygen() error {
	c := exec.Command(rosenpassExecutable, "keygen")

	skPath, skBuf, err := bufferedReader(c)
	if err != nil {
		return err
	} else {
		c.Args = append(c.Args, "private-key", skPath)
	}

	pkPath, pkBuf, err := bufferedReader(c)
	if err != nil {
		return err
	} else {
		c.Args = append(c.Args, "public-key", pkPath)
	}

	if err := c.Run(); err != nil {
		return err
	}

	rp.privateKey = skBuf.Bytes()
	rp.publicKey = pkBuf.Bytes()

	return nil
}

func (rp *Rosenpass) Exchange() (*exec.Cmd, error) {
	c := exec.Command(rosenpassExecutable, "exchange")

	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	if skPath, err := bufferedWriter(c, rp.privateKey); err != nil {
		return nil, err
	} else {
		c.Args = append(c.Args, "private-key", skPath)
	}

	if pkPath, err := bufferedWriter(c, rp.publicKey); err != nil {
		return nil, err
	} else {
		c.Args = append(c.Args, "public-key", pkPath)
	}

	if rp.Verbose {
		c.Args = append(c.Args, "verbose")
	}

	if la := rp.ListenAddr; la != nil {
		c.Args = append(c.Args, "listen", udpAddr(la))
	}

	for _, peer := range rp.Peers {
		pkPath, err := bufferedWriter(c, peer.PublicKey)
		if err != nil {
			return nil, err
		} else {
			c.Args = append(c.Args, "peer", "public-key", pkPath)
		}

		if outputPath, err := peer.outfileReader(c); err != nil {
			return nil, err
		} else {
			c.Args = append(c.Args, "outfile", outputPath)
		}

		if ep := peer.Endpoint; ep != nil {
			c.Args = append(c.Args, "endpoint", udpAddr(ep))
		}

		if peer.PresharedKey != nil {
			if pskPath, err := bufferedWriter(c, peer.PresharedKey); err != nil {
				return nil, err
			} else {
				c.Args = append(c.Args, "preshared-key", pskPath)
			}
		}

		if peer.WireGuardDev != "" && peer.WireGuardPeer != nil {
			c.Args = append(c.Args, "wireguard", peer.WireGuardDev, base64.RawStdEncoding.EncodeToString(peer.WireGuardPeer))
			c.Args = append(c.Args, peer.WireGuardExtraParams...)
		}
	}

	log.Printf("Starting rosenpass %s", strings.Join(c.Args, " "))

	return c, nil
}

func (p *Peer) outfileReader(c *exec.Cmd) (string, error) {
	if p.Keys == nil {
		return "/dev/null", nil
	}

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

			key := make([]byte, 32)
			if n, err := base64.StdEncoding.Decode(key, buf[:n]); err != nil {
				log.Fatalf("Failed to decode key: %s", err)
			} else if n != 32 {
				log.Fatalf("Partial read: %d", n)
			}

			p.Keys <- key
		}
	}()

	i := len(c.ExtraFiles) + 3
	c.ExtraFiles = append(c.ExtraFiles, wr)

	return fmt.Sprintf("/dev/fd/%d", i), nil
}

func bufferedReader(c *exec.Cmd) (string, *bytes.Buffer, error) {
	rd, wr, err := os.Pipe()
	if err != nil {
		return "", nil, fmt.Errorf("failed to create pipe: %w", err)
	}

	buf := &bytes.Buffer{}

	go func() {
		if _, err := io.Copy(buf, rd); err != nil {
			log.Fatalf("Failed to copy: %s", err)
		}
	}()

	i := len(c.ExtraFiles) + 3
	c.ExtraFiles = append(c.ExtraFiles, wr)

	return fmt.Sprintf("/dev/fd/%d", i), buf, nil
}

func bufferedWriter(c *exec.Cmd, b []byte) (string, error) {
	rd, wr, err := os.Pipe()
	if err != nil {
		return "", fmt.Errorf("failed to create pipe: %w", err)
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

	i := len(c.ExtraFiles) + 3
	c.ExtraFiles = append(c.ExtraFiles, rd)

	return fmt.Sprintf("/dev/fd/%d", i), nil
}

func udpAddr(a *net.UDPAddr) string {
	if a.Port == 0 {
		return a.IP.String()
	} else {
		return a.String()
	}
}
