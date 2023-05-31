// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

// Handler is on of the supported handlers declared below.
type Handler any

type HandshakeCompletedHandler interface {
	HandshakeCompleted(pid, key)
}

type HandshakeExpiredHandler interface {
	HandshakeExpired(pid)
}
