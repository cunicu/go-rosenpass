// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"bytes"
	"log/slog"
	"os/exec"
	"strings"

	rp "cunicu.li/go-rosenpass"
)

type ExchangeCommandHandler struct {
	peers map[rp.PeerID][]string
}

func NewExchangeCommandHandler() *ExchangeCommandHandler {
	return &ExchangeCommandHandler{
		peers: map[rp.PeerID][]string{},
	}
}

func (h *ExchangeCommandHandler) AddPeer(pid rp.PeerID, cmd []string) {
	h.peers[pid] = cmd
}

func (h *ExchangeCommandHandler) RemovePeer(pid rp.PeerID) {
	delete(h.peers, pid)
}

func (h *ExchangeCommandHandler) HandshakeCompleted(pid rp.PeerID, key rp.Key) {
	cmd, ok := h.peers[pid]
	if !ok || len(cmd) < 1 {
		return
	}

	out := &bytes.Buffer{}

	c := exec.Command(cmd[0], cmd[1:]...) // nolint:gosec
	c.Stdin = strings.NewReader(key.String() + "\n")
	c.Stdout = out
	c.Stderr = out

	go func() {
		if err := c.Run(); err != nil {
			outStr := strings.TrimSpace(out.String())
			slog.Error("Failed to run command",
				slog.Any("error", err),
				slog.String("output", outStr))
		}
	}()
}
