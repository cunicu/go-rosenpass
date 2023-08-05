// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build !wgcmd && cgo && (freebsd || openbsd)

package config

import (
	"fmt"

	rp "github.com/stv0g/go-rosenpass"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wireGuardHandler struct {
	client *wgctrl.Client
	peers  map[rp.PeerID]WireGuardSection
}

func newWireGuardHandler() (hdlr *wireGuardHandler, err error) {
	hdlr = &wireGuardHandler{
		peers: map[rp.PeerID]WireGuardSection{},
	}

	if hdlr.client, err = wgctrl.New(); err != nil {
		return nil, fmt.Errorf("failed to creat WireGuard client: %w", err)
	}

	return hdlr, nil
}

func (h *wireGuardHandler) outputKey(_ rp.KeyOutputReason, pid rp.PeerID, psk rp.Key) {
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
