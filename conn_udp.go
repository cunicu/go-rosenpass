// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/exp/slog"
)

type udpEndpoint struct {
	*net.UDPAddr
}

func (ep *udpEndpoint) Equal(o endpoint) bool {
	ep2, ok := o.(*udpEndpoint)
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

type udpConn struct {
	listenAddrs []*net.UDPAddr
	conns       map[string]*net.UDPConn

	logger *slog.Logger
}

func newUDPConn(la []*net.UDPAddr) (*udpConn, error) {
	return &udpConn{
		listenAddrs: la,
		conns:       map[string]*net.UDPConn{},
		logger:      slog.Default(),
	}, nil
}

func (s *udpConn) Close() error {
	for _, conn := range s.conns {
		if err := conn.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (s *udpConn) Send(pl payload, spkt spk, ep endpoint) error {
	uep, ok := ep.(*udpEndpoint)
	if !ok {
		return errors.New("invalid endpoint type")
	}

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

	network := networkFromAddr(uep.UDPAddr)

	// Check if we are on DragonFly or OpenBSD systems
	// which require two independent sockets for listening
	// on IPv4 and IPv6 simultaneously
	conn, ok := s.conns[network]
	if !ok {
		if conn, ok = s.conns["udp"]; !ok { // Fallback
			return fmt.Errorf("failed to find socket with matching address family")
		}
	}

	buf := e.MarshalBinaryAndSeal(spkt)
	if n, err := conn.WriteToUDP(buf, uep.UDPAddr); err != nil {
		return err
	} else if n != len(buf) {
		return fmt.Errorf("partial write")
	}

	return nil
}

func (s *udpConn) open(networks map[string]*net.UDPAddr) ([]receiveFunc, error) {
	recvFncs := []receiveFunc{}

	for network, listenAddr := range networks {
		conn, err := net.ListenUDP(network, listenAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen: %w", err)
		}

		s.logger.Debug("Started listening", slog.Any("addr", listenAddr))

		s.conns[network] = conn
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

func receiveFromConn(conn *net.UDPConn) receiveFunc {
	return func(spkm spk) (payload, endpoint, error) {
		// TODO: Check for appropriate MTU
		buf := make([]byte, 1500)

		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read: %w", err)
		}

		e := &envelope{}
		if m, err := e.CheckAndUnmarshalBinary(buf[:n], spkm); err != nil {
			return nil, nil, fmt.Errorf("received malformed packet: %w", err)
		} else if m != n {
			return nil, nil, fmt.Errorf("parsed partial packet")
		}

		return e.payload, &udpEndpoint{from}, nil
	}
}
