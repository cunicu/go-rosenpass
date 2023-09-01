// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package rosenpass

import (
	"errors"
	"net"
)

type SinglePortUDPConn struct{}

func NewSinglePortUDPConn(la []*net.UDPAddr) (*SinglePortUDPConn, error) {
	return nil, errors.ErrUnsupported
}
