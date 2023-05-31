// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	rp "github.com/stv0g/go-rosenpass"
	"golang.org/x/exp/slog"
)

type keyoutFileHandler struct {
	peers map[rp.PeerID]string
}

func (h *keyoutFileHandler) addPeerKeyoutFile(pid rp.PeerID, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create dir: %w", err)
	}

	h.peers[pid] = path

	return nil
}

func (h *keyoutFileHandler) HandshakeCompleted(pid rp.PeerID, key rp.Key) {
	fn, ok := h.peers[pid]
	if !ok {
		return
	}

	b64Key := base64.StdEncoding.EncodeToString(key[:])
	if err := os.WriteFile(fn, []byte(b64Key), 0o600); err != nil {
		slog.Error("Failed to write", slog.Any("error", err))
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
