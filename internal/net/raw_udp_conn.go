// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package net

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/mdlayher/socket"
	"golang.org/x/sys/unix"
)

const (
	// Socket option to attach a classic BPF program to the socket for
	// use as a filter of incoming packets.
	SoAttachFilter int = 26

	// Socket option to attach an extended BPF program to the socket for
	// use as a filter of incoming packets.
	SoAttachBPF int = 50
)

var IPv4Unspecified = net.IPv4(0, 0, 0, 0)

type RawUDPConn struct {
	conn *socket.Conn

	localAddr *net.UDPAddr
	closed    bool

	logger *slog.Logger
}

func ListenRawUDP(network string, addr *net.UDPAddr) (c *RawUDPConn, err error) {
	if addr == nil {
		addr = &net.UDPAddr{}
	}

	if addr.Port == 0 {
		port, err := rand.Int(rand.Reader, big.NewInt(65535-1024))
		if err != nil {
			return nil, err
		}

		addr.Port = 1024 + int(port.Int64())
	}

	if addr.IP == nil {
		switch network {
		case "udp6":
			addr.IP = net.IPv6unspecified
		case "udp4":
			addr.IP = IPv4Unspecified
		default:
			return nil, fmt.Errorf("unsupported network: %s", network)
		}
	}

	c = &RawUDPConn{
		localAddr: addr,
		logger:    slog.With(slog.String("name", "fuc")),
	}

	sa := addrToSockaddr(addr)
	af := 0
	switch sa.(type) {
	case *unix.SockaddrInet4:
		af = unix.AF_INET
	case *unix.SockaddrInet6:
		af = unix.AF_INET6
	default:
		return nil, fmt.Errorf("unsupported network")
	}

	if c.conn, err = socket.Socket(af, unix.SOCK_RAW, unix.IPPROTO_UDP, "raw"+fmt.Sprint(af), nil); err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	if err := c.conn.Bind(sa); err != nil {
		c.conn.Close()
		return nil, fmt.Errorf("failed to bind socket: %w", err)
	}

	return c, nil
}

func (c *RawUDPConn) Close() error {
	c.closed = true
	return c.conn.Close()
}

func (c *RawUDPConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *RawUDPConn) ReadFrom(buf []byte) (n int, addr net.Addr, err error) {
	if c.closed {
		return -1, nil, net.ErrClosed
	}

	n, ra, err := c.conn.Recvfrom(context.Background(), buf, 0)
	if err != nil {
		return -1, nil, err
	}

	var ip net.IP
	var decoder gopacket.Decoder

	switch ra := ra.(type) {
	case *unix.SockaddrInet6:
		decoder = layers.LayerTypeUDP
		ip = ra.Addr[:]
	case *unix.SockaddrInet4:
		decoder = layers.LayerTypeIPv4
		ip = ra.Addr[:]
	default:
		return -1, nil, fmt.Errorf("received invalid address family")
	}

	packet := gopacket.NewPacket(buf[:n], decoder, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})

	// f.logger.Debug("Received packet",
	// 	slog.Any("remote_address", ip),
	// 	slog.Any("buf", hex.EncodeToString(pkt.Buffer)),
	// 	slog.Any("decoder", decoder),
	// )

	// os.Stdout.Write([]byte(packet.Dump()))

	transport := packet.TransportLayer()
	if transport == nil {
		return -1, nil, fmt.Errorf("failed to decode packet")
	}

	udp, ok := transport.(*layers.UDP)
	if !ok {
		return -1, nil, fmt.Errorf("invalid layer type")
	}

	pl := packet.ApplicationLayer()
	n = len(pl.Payload())

	copy(buf[:n], pl.Payload())

	rAddrUDP := &net.UDPAddr{
		IP:   ip,
		Port: int(udp.SrcPort),
	}

	return n, rAddrUDP, nil
}

func (c *RawUDPConn) WriteTo(buf []byte, rAddr net.Addr) (n int, err error) {
	if c.closed {
		return -1, net.ErrClosed
	}

	rUDPAddr, ok := rAddr.(*net.UDPAddr)
	if !ok {
		return -1, fmt.Errorf("invalid address type")
	}

	buffer := gopacket.NewSerializeBuffer()
	payload := gopacket.Payload(buf)

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(c.localAddr.Port), // nolint: gosec
		DstPort: layers.UDPPort(rUDPAddr.Port), // nolint: gosec
	}

	var nwLayer gopacket.NetworkLayer
	if isIPv6 := rUDPAddr.IP.To4() == nil; isIPv6 {
		nwLayer = &layers.IPv6{
			SrcIP: net.IPv6zero,
			DstIP: rUDPAddr.IP,
		}
	} else {
		nwLayer = &layers.IPv4{
			SrcIP: net.IPv4zero,
			DstIP: rUDPAddr.IP,
		}
	}

	if err := udp.SetNetworkLayerForChecksum(nwLayer); err != nil {
		return -1, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	seropts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buffer, seropts, udp, payload); err != nil {
		return -1, fmt.Errorf("failed serialize packet: %s", err)
	}

	// f.logger.Debug("Sending packet",
	// 	slog.Any("remote_address", rSockAddr),
	// 	slog.Any("buf", hex.EncodeToString(buf)))

	return len(buf), c.conn.Sendto(
		context.Background(),
		buffer.Bytes(), 0,
		addrToSockaddr(rUDPAddr))
}

func (c *RawUDPConn) SetDeadline(t time.Time) error {
	if err := c.SetWriteDeadline(t); err != nil {
		return err
	}

	return c.SetReadDeadline(t)
}

func (c *RawUDPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *RawUDPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// FilterEBpf attaches an BPF filter program to the connection.
func (c *RawUDPConn) FilterEBpf(ins asm.Instructions) error {
	spec := ebpf.ProgramSpec{
		Type:         ebpf.SocketFilter,
		License:      "GPL",
		Instructions: ins,
	}

	prog, err := ebpf.NewProgramWithOptions(&spec, ebpf.ProgramOptions{
		LogLevel: 6,
	})
	if err != nil {
		return err
	}

	return c.conn.SetsockoptInt(unix.SOL_SOCKET, SoAttachBPF, prog.FD())
}

func addrToSockaddr(addr *net.UDPAddr) (sa unix.Sockaddr) {
	isIPv6 := addr.IP.To4() == nil

	if isIPv6 {
		saInet6 := &unix.SockaddrInet6{}
		copy(saInet6.Addr[:], addr.IP.To16())
		sa = saInet6
	} else {
		saInet4 := &unix.SockaddrInet4{}
		copy(saInet4.Addr[:], addr.IP.To4())
		sa = saInet4
	}

	return sa
}
