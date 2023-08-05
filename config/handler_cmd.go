// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os/exec"
	"strings"

	rp "github.com/stv0g/go-rosenpass"
	"golang.org/x/exp/slog"
)

type exchangeCommandHandler struct {
	peers map[rp.PeerID][]string
}

func newExchangeCommandHandler() *exchangeCommandHandler {
	return &exchangeCommandHandler{
		peers: map[rp.PeerID][]string{},
	}
}

func (h *exchangeCommandHandler) addPeerCommand(pid rp.PeerID, cmd []string) {
	h.peers[pid] = cmd
}

func (h *exchangeCommandHandler) HandshakeCompleted(pid rp.PeerID, key rp.Key) {
	cmd, ok := h.peers[pid]
	if !ok || len(cmd) < 1 {
		return
	}

	c := exec.Command(cmd[0], cmd[1:]...) // nolint:gosec
	c.Stdin = strings.NewReader(key.String() + "\n")

	go func() {
		if err := c.Run(); err != nil {
			slog.Error("Failed to run exchange command", "error", err)
		}
	}()
}
