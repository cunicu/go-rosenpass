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
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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

	c := exec.Command(cmd[0], cmd[1:]...)
	c.Stdin = strings.NewReader(key.String() + "\n")

	go func() {
		if err := c.Run(); err != nil {
			slog.Error("Failed to run exchange command", "error", err)
		}
	}()
}

type wireGuardHandler struct {
	client *wgctrl.Client
	peers  map[rp.PeerID]WireGuardSection
}

func newWireGuardHandler() (hdlr *wireGuardHandler, err error) {
	hdlr = &wireGuardHandler{}

	if hdlr.client, err = wgctrl.New(); err != nil {
		return nil, fmt.Errorf("failed to creat WireGuard client: %w", err)
	}

	return hdlr, nil
}

func (h *wireGuardHandler) addPeer(pid rp.PeerID, wg WireGuardSection) {
	h.peers[pid] = wg
}

func (h *wireGuardHandler) HandshakeCompleted(pid rp.PeerID, key rp.Key) {
	h.outputKey(rp.KeyOutputReasonStale, pid, key)
}

func (h *wireGuardHandler) HandshakeExpired(pid rp.PeerID) {
	key, _ := rp.GeneratePresharedKey()
	h.outputKey(rp.KeyOutputReasonStale, pid, key)
}

func (h *wireGuardHandler) outputKey(reason rp.KeyOutputReason, pid rp.PeerID, psk rp.Key) {
	wg, ok := h.peers[pid]
	if !ok {
		return
	}

	if err := h.client.ConfigureDevice(wg.Interface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				UpdateOnly:   true,
				PublicKey:    wgtypes.Key(wg.PublicKey),
				PresharedKey: (*wgtypes.Key)(&psk),
			},
		},
	}); err != nil {
		slog.Error("Failed to configure WireGuard peer",
			slog.Any("interface", wg.Interface),
			slog.Any("peer", wg.PublicKey))
	}
}
