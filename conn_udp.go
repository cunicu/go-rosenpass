// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"fmt"
	"net"

	"golang.org/x/exp/slog"
)

//nolint:unused
type endpoint interface {
	String() string
	Equal(endpoint) bool
}

type conn interface {
	Send(pl payload, p *peer) error
	Receive(spkm spk) (payload, *net.UDPAddr, error)
	Close() error
}

type udpConn struct {
	conn *net.UDPConn

	logger *slog.Logger
}

func newUDPConn(la *net.UDPAddr) (*udpConn, error) {
	conn, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	return &udpConn{
		conn:   conn,
		logger: slog.Default(),
	}, nil
}

func (s *udpConn) Send(pl payload, p *peer) error {
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

	buf := e.MarshalBinaryAndSeal(p.spkt)
	if n, err := s.conn.WriteToUDP(buf, p.endpoint); err != nil {
		return err
	} else if n != len(buf) {
		return fmt.Errorf("partial write")
	}

	return nil
}

func (s *udpConn) Receive(spkm spk) (payload, *net.UDPAddr, error) {
	// TODO: Check for appropriate MTU
	buf := make([]byte, 1500)

	n, from, err := s.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read: %w", err)
	}

	e := &envelope{}
	if m, err := e.CheckAndUnmarshalBinary(buf[:n], spkm); err != nil {
		return nil, nil, fmt.Errorf("received malformed packet: %w", err)
	} else if m != n {
		return nil, nil, fmt.Errorf("parsed partial packet")
	}

	return e.payload, from, nil
}

func (s *udpConn) Close() error {
	return s.conn.Close()
}

func compareAddr(a, b *net.UDPAddr) bool {
	if !a.IP.Equal(b.IP) {
		return false
	}

	if a.Port != b.Port {
		return false
	}

	return true
}
