// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
)

var _ Conn = (*UDPConn)(nil)

var errInvalidEndpoint = errors.New("invalid endpoint type")

type udpEndpoint struct {
	*net.UDPAddr
}

func (ep *udpEndpoint) Equal(o Endpoint) bool {
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

func (s *UDPConn) Close() error {
	for _, conn := range s.conns {
		if err := conn.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (s *UDPConn) Send(pl Payload, spkt spk, ep Endpoint) error {
	uep, ok := ep.(*udpEndpoint)
	if !ok {
		return errInvalidEndpoint
	}

	var msgType msgType
	var msgSize int

	switch pl.(type) {
	case *initHello:
		msgType = msgTypeInitHello
		msgSize = initHelloMsgSize
	case *respHello:
		msgType = msgTypeRespHello
		msgSize = respHelloMsgSize
	case *initConf:
		msgType = msgTypeInitConf
		msgSize = initConfMsgSize
	case *emptyData:
		msgType = msgTypeEmptyData
		msgSize = emptyDataMsgSize
	}

	env := Envelope{
		typ:     msgType,
		payload: pl,
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

	// Pre-allocate full buffer for efficiency
	buf := make([]byte, 0, envelopeSize+msgSize)
	buf = env.MarshalBinaryAndSeal(spkt, buf)

	if n, err := conn.WriteToUDP(buf, uep.UDPAddr); err != nil {
		return err
	} else if n != len(buf) {
		return fmt.Errorf("partial write")
	}

	return nil
}

func (s *UDPConn) open(networks map[string]*net.UDPAddr) ([]ReceiveFunc, error) {
	recvFncs := []ReceiveFunc{}

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

func receiveFromConn(conn *net.UDPConn) ReceiveFunc {
	return func(spkm spk, buf []byte) (Payload, Endpoint, error) {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read: %w", err)
		}

		e := &Envelope{}
		if m, err := e.CheckAndUnmarshalBinary(buf[:n], spkm); err != nil {
			return nil, nil, fmt.Errorf("received malformed packet: %w", err)
		} else if m != n {
			return nil, nil, fmt.Errorf("parsed partial packet")
		}

		return e.payload, &udpEndpoint{from}, nil
	}
}
