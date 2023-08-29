// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"log/slog"
	"net"
)

type Config struct {
	ListenAddrs []*net.UDPAddr

	PublicKey spk
	SecretKey ssk

	Peers    []PeerConfig
	Handlers []Handler

	Conn Conn

	Logger *slog.Logger
}
