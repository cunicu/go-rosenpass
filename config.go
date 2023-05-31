// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"net"

	"golang.org/x/exp/slog"
)

type Config struct {
	Listen *net.UDPAddr

	PublicKey spk
	SecretKey ssk

	Peers    []PeerConfig
	Handlers []HandshakeHandler // TODO: Use any? for API extensibility?

	Conn conn

	Logger *slog.Logger
}
