// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	rp "cunicu.li/go-rosenpass"
)

type keyoutFileHandler struct {
	peers map[rp.PeerID]string
}

func newkeyoutHandler() *keyoutFileHandler {
	return &keyoutFileHandler{
		peers: map[rp.PeerID]string{},
	}
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
	h.outputKey(rp.KeyOutputReasonExchanged, pid, key)
}

func (h *keyoutFileHandler) HandshakeExpired(pid rp.PeerID) {
	key, _ := rp.GeneratePresharedKey()
	h.outputKey(rp.KeyOutputReasonStale, pid, key)
}

func (h *keyoutFileHandler) outputKey(reason rp.KeyOutputReason, pid rp.PeerID, key rp.Key) {
	fn, ok := h.peers[pid]
	if !ok {
		return
	}

	b64Key := base64.StdEncoding.EncodeToString(key[:])
	if err := os.WriteFile(fn, []byte(b64Key), 0o600); err != nil {
		slog.Error("Failed to write", slog.Any("error", err))
	}

	ko := rp.KeyOutput{
		Peer:    pid,
		KeyFile: fn,
		Why:     reason,
	}
	fmt.Fprintln(os.Stdout, ko.String())
}
