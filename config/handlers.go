// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	rp "github.com/stv0g/go-rosenpass"
	"golang.org/x/exp/slog"
)

type keyoutFileHandler struct {
	peers map[rp.PeerID]io.Writer
}

func (h *keyoutFileHandler) addPeerKeyoutFile(pid rp.PeerID, path string) error {
	if wr, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600); err != nil {
		return err
	} else {
		h.peers[pid] = wr
		return nil
	}
}

func (h *keyoutFileHandler) HandshakeCompleted(pid rp.PeerID, key rp.Key) {
	if wr, ok := h.peers[pid]; ok {
		fmt.Fprintln(wr, base64.StdEncoding.EncodeToString(key[:]))
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
