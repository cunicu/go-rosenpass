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
	"os"
	"os/exec"

	rp "github.com/stv0g/go-rosenpass"
)

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
