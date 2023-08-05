// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build !cgo && (freebsd || openbsd)

package config

import (
	rp "github.com/stv0g/go-rosenpass"
)

type wireGuardHandler struct {
	*exchangeCommandHandler
}

func newWireGuardHandler() (hdlr *wireGuardHandler, err error) {
	return &wireGuardHandler{newExchangeCommandHandler()}, nil
}

func (h *wireGuardHandler) addPeer(pid rp.PeerID, wg WireGuardSection) {
	h.exchangeCommandHandler.addPeerCommand(pid, []string{
		"wg",
		"set", wg.Interface,
		"peer", wg.PublicKey.String(),
		"preshared-key", "/dev/stdin",
	})
}
