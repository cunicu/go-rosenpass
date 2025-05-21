// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package rosenpass

import (
	"errors"
	"net"
)

var _ Conn = (*SinglePortUDPConn)(nil)

type SinglePortUDPConn struct{}

func NewSinglePortUDPConn(_ []*net.UDPAddr) (*SinglePortUDPConn, error) {
	return nil, errors.ErrUnsupported
}

func (c *SinglePortUDPConn) Close() error {
	return errors.ErrUnsupported
}

func (c *SinglePortUDPConn) Open() ([]ReceiveFunc, error) {
	return nil, errors.ErrUnsupported
}

func (c *SinglePortUDPConn) Send(_ payload, _ spk, _ Endpoint) error {
	return errors.ErrUnsupported
}

func (c *SinglePortUDPConn) LocalEndpoints() ([]Endpoint, error) {
	return nil, errors.ErrUnsupported
}
