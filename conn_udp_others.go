// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build !(dragonfly || openbsd)

package rosenpass

import (
	"fmt"
	"net"
)

func (s *UDPConn) Open() ([]ReceiveFunc, error) {
	networks := map[string]*net.UDPAddr{}

	for _, la := range s.listenAddrs {
		network := networkFromAddr(la)
		if la2, ok := networks[network]; ok {
			return nil, fmt.Errorf("already listing for %s on %s", network, la2)
		}

		networks[network] = la
	}

	return s.open(networks)
}
