// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
)

var errInvalidEndpoint = errors.New("invalid endpoint type")

type UDPEndpoint net.UDPAddr

func NewUDPEndpoint(s string) (*UDPEndpoint, error) {
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, err
	}

	return (*UDPEndpoint)(addr), nil
}

func (ep *UDPEndpoint) String() string {
	addr := (*net.UDPAddr)(ep)
	return addr.String()
}

func (ep UDPEndpoint) Equal(o Endpoint) bool {
	ep2, ok := o.(*UDPEndpoint)
	if !ok {
		return false
	}

	if !ep.IP.Equal(ep2.IP) {
		return false
	}

	if ep.Port != ep2.Port {
		return false
	}

	return true
}

type UDPConn struct {
	listenAddrs []*net.UDPAddr
	conns       map[string]*net.UDPConn

	logger *slog.Logger
}

func NewUDPConn(la []*net.UDPAddr) (*UDPConn, error) {
	return &UDPConn{
		listenAddrs: la,
		conns:       map[string]*net.UDPConn{},
		logger:      slog.Default(),
	}, nil
}

func (c *UDPConn) Close() error {
	for _, conn := range c.conns {
		if err := conn.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (c *UDPConn) Send(pl payload, spkt spk, ep Endpoint) error {
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

func (c *UDPConn) LocalEndpoints() (eps []Endpoint, err error) {
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

func (c *UDPConn) open(networks map[string]*net.UDPAddr) ([]ReceiveFunc, error) {
	recvFncs := []ReceiveFunc{}

	for network, listenAddr := range networks {
		conn, err := net.ListenUDP(network, listenAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen: %w", err)
		}

		c.logger.Debug("Started listening", slog.Any("addr", listenAddr))

		c.conns[network] = conn
		recvFncs = append(recvFncs, receiveFromConn(conn))
	}

	return recvFncs, nil
}

func networkFromAddr(a *net.UDPAddr) string {
	if a.IP == nil {
		return "udp"
	}

	if isIPv4 := a.IP.To4() != nil; isIPv4 {
		return "udp4"
	}

	return "udp6"
}

func receiveFromConn(conn net.PacketConn) ReceiveFunc {
	return func(spkm spk) (payload, Endpoint, error) {
		// TODO: Check for appropriate MTU
		buf := make([]byte, 1500)

		n, rAddr, err := conn.ReadFrom(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read: %w", err)
		}

		e := &envelope{}
		if m, err := e.CheckAndUnmarshalBinary(buf[:n], spkm); err != nil {
			return nil, nil, fmt.Errorf("received malformed packet: %w", err)
		} else if m != n {
			return nil, nil, fmt.Errorf("parsed partial packet")
		}

		rAddrUDP, ok := rAddr.(*net.UDPAddr)
		if !ok {
			return nil, nil, errors.New("invalid remote address type")
		}

		return e.payload, (*UDPEndpoint)(rAddrUDP), nil
	}
}

func sendToConn(conn net.PacketConn, addr net.Addr, pl payload, spkt spk) error {
	e := envelope{
		payload: pl,
	}

	switch pl.(type) {
	case *initHello:
		e.typ = msgTypeInitHello
	case *respHello:
		e.typ = msgTypeRespHello
	case *initConf:
		e.typ = msgTypeInitConf
	case *emptyData:
		e.typ = msgTypeEmptyData
	}

	buf := e.MarshalBinaryAndSeal(spkt)

	if n, err := conn.WriteTo(buf, addr); err != nil {
		return err
	} else if n != len(buf) {
		return fmt.Errorf("partial write")
	}

	return nil
}
