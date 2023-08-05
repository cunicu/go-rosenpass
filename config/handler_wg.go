// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	rp "github.com/stv0g/go-rosenpass"
)

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
