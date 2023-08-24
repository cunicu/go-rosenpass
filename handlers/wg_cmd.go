// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build !cgo && (freebsd || openbsd)

package handlers

import (
	rp "cunicu.li/go-rosenpass"
)

type WireGuardHandler struct {
	*ExchangeCommandHandler
}

func NewWireGuardHandler() (hdlr *WireGuardHandler, err error) {
	return &WireGuardHandler{NewExchangeCommandHandler()}, nil
}

func (h *WireGuardHandler) AddPeer(pid rp.PeerID, intf string, pk rp.Key) {
	h.ExchangeCommandHandler.AddPeerCommand(pid, []string{
		"wg",
		"set", intf,
		"peer", pk.String(),
		"preshared-key", "/dev/stdin",
	})
}
