// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build cgo || !(freebsd || openbsd)

package handlers

import (
	"fmt"
	"log/slog"

	rp "cunicu.li/go-rosenpass"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wireGuardPeer struct {
	Interface string
	PublicKey rp.Key
}

type WireGuardHandler struct {
	client *wgctrl.Client
	peers  map[rp.PeerID]wireGuardPeer
}

func NewWireGuardHandler() (hdlr *WireGuardHandler, err error) {
	hdlr = &WireGuardHandler{
		peers: map[rp.PeerID]wireGuardPeer{},
	}

	if hdlr.client, err = wgctrl.New(); err != nil {
		return nil, fmt.Errorf("failed to creat WireGuard client: %w", err)
	}

	return hdlr, nil
}

func (h *WireGuardHandler) AddPeer(pid rp.PeerID, intf string, pk rp.Key) {
	h.peers[pid] = wireGuardPeer{
		Interface: intf,
		PublicKey: pk,
	}
}

func (h *WireGuardHandler) HandshakeCompleted(pid rp.PeerID, key rp.Key) {
	h.outputKey(rp.KeyOutputReasonStale, pid, key)
}

func (h *WireGuardHandler) HandshakeExpired(pid rp.PeerID) {
	key, _ := rp.GeneratePresharedKey()
	h.outputKey(rp.KeyOutputReasonStale, pid, key)
}

func (h *WireGuardHandler) outputKey(_ rp.KeyOutputReason, pid rp.PeerID, psk rp.Key) {
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
			slog.Any("peer", wg.PublicKey),
			slog.Any("error", err))
	}
}
