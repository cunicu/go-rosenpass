// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package rosenpass

import (
	"fmt"
	"log/slog"
	"net"

	ebpfx "cunicu.li/go-rosenpass/internal/ebpf"
	netx "cunicu.li/go-rosenpass/internal/net"
)

type SinglePortUDPConn struct {
	listenAddrs []*net.UDPAddr
	conns       map[string]*netx.RawUDPConn

	logger *slog.Logger
}

func NewSinglePortUDPConn(la []*net.UDPAddr) (*SinglePortUDPConn, error) {
	return &SinglePortUDPConn{
		listenAddrs: la,
		conns:       map[string]*netx.RawUDPConn{},
		logger:      slog.Default(),
	}, nil
}

func (c *SinglePortUDPConn) Close() error {
	for _, conn := range c.conns {
		if err := conn.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (c *SinglePortUDPConn) Send(pl payload, spkt spk, ep Endpoint) error {
	uep, ok := ep.(*UDPEndpoint)
	if !ok {
		return errInvalidEndpoint
	}

	addr := (*net.UDPAddr)(uep)
	network := networkFromAddr(addr)

	// Check if we are on DragonFly or OpenBSD systems
	// which require two independent sockets for listening
	// on IPv4 and IPv6 simultaneously
	conn, ok := c.conns[network]
	if !ok {
		if conn, ok = c.conns["udp"]; !ok { // Fallback
			return fmt.Errorf("failed to find socket with matching address family")
		}
	}

	return sendToConn(conn, addr, pl, spkt)
}

func (c *SinglePortUDPConn) Open() (recvFncs []ReceiveFunc, err error) {
	networks := map[string]*net.UDPAddr{}

	for _, la := range c.listenAddrs {
		if network := networkFromAddr(la); network == "udp" {
			networks["udp4"] = la
			networks["udp6"] = la
		} else {
			networks[network] = la
		}
	}

	for network, lAddr := range networks {
		conn, err := netx.ListenRawUDP(network, lAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen: %w", err)
		}

		if err = conn.FilterEBpf(ebpfx.RosenpassFilterEbpf(lAddr.Port)); err != nil {
			return nil, fmt.Errorf("failed to apply eBPF filter: %w", err)
		}

		c.logger.Debug("Started listening", slog.Any("addr", lAddr))

		c.conns[network] = conn
		recvFncs = append(recvFncs, receiveFromConn(conn))
	}

	return recvFncs, nil
}

func (c *SinglePortUDPConn) LocalEndpoints() (eps []Endpoint, err error) {
	for _, sc := range c.conns {
		la := sc.LocalAddr()
		lua, ok := la.(*net.UDPAddr)
		if !ok {
			return nil, fmt.Errorf("invalid address type encountered")
		}

		eps = append(eps, (*UDPEndpoint)(lua))
	}

	return eps, nil
}
