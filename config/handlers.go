// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	rp "github.com/stv0g/go-rosenpass"
	"golang.org/x/exp/slog"
)

type keyoutFileHandler struct {
	peers map[rp.PeerID]io.WriteSeeker
}

func (h *keyoutFileHandler) addPeerKeyoutFile(pid rp.PeerID, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create dir: %w", err)
	}

	if wr, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err != nil {
		return err
	} else {
		h.peers[pid] = wr
		return nil
	}
}

func (h *keyoutFileHandler) HandshakeCompleted(pid rp.PeerID, key rp.Key) {
	if wr, ok := h.peers[pid]; ok {
		if _, err := wr.Seek(0, io.SeekStart); err != nil {
			slog.Error("Failed to seek", slog.Any("error", err))
		}

		if _, err := fmt.Fprintln(wr, base64.StdEncoding.EncodeToString(key[:])); err != nil {
			slog.Error("Failed to write", slog.Any("error", err))
		}
	}
}

type exchangeCommandHandler struct {
	peers map[rp.PeerID][]string
}

func (h *exchangeCommandHandler) addPeerCommand(pid rp.PeerID, cmd []string) {
	h.peers[pid] = cmd
}

func (h *exchangeCommandHandler) HandshakeCompleted(pid rp.PeerID, key rp.Key) {
	cmd, ok := h.peers[pid]
	if !ok || len(cmd) < 1 {
		return
	}

	c := exec.Command(cmd[0], cmd[1:]...)
	c.Stdin = strings.NewReader(key.String() + "\n")

	go func() {
		if err := c.Run(); err != nil {
			slog.Error("Failed to run exchange command", "error", err)
		}
	}()
}
