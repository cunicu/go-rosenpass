// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package net_test

import (
	"net"
	"os"
	"testing"
	"time"

	ebpfx "cunicu.li/go-rosenpass/internal/ebpf"
	netx "cunicu.li/go-rosenpass/internal/net"
	"github.com/stretchr/testify/require"
)

func test(t *testing.T, shouldSucceed bool, msg []byte, lAddr, rAddr *net.UDPAddr) {
	require := require.New(t)

	network := "udp4"
	if lAddr.IP.To4() == nil {
		network = "udp6"
	}

	c1, err := netx.ListenRawUDP(network, nil)
	require.NoError(err, "Failed to open socket: %s", err)
	defer c1.Close()

	c2, err := netx.ListenRawUDP(network, lAddr)
	require.NoError(err, "Failed to create filtered UDP connection: %s", err)
	defer c2.Close()

	err = c2.FilterEBpf(ebpfx.RosenpassFilterEbpf(lAddr.Port))
	require.NoError(err, "Failed to apply eBPF filter: %s", err)

	_, err = c1.WriteTo(msg, rAddr)
	require.NoError(err, "Failed to send packet: %s", err)

	// Invalid messages should never pass the filter
	// So we set a timeout here and assert that the timeout will expire
	if shouldSucceed {
		err = c2.SetDeadline(time.Time{}) // Reset
	} else {
		err = c2.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	}
	require.NoError(err)

	recvMsg := make([]byte, 1024)
	n, _, err := c2.ReadFrom(recvMsg)
	if shouldSucceed {
		require.NoError(err, "Failed to read from connection: %s", err)
		require.Len(msg, n, "mismatching length")
		require.Equal(msg, recvMsg[:n], "mismatching contents")
	} else {
		err, isNetError := err.(net.Error)
		require.True(isNetError, "invalid error type: %s", err)
		require.True(err.Timeout(), "error is not a timeout")
	}
}

func TestRawUDPConn(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Single port require root privileges")
	}

	dataRosenpass := []byte{0x81, 0x01, 0x02, 0x03}
	dataWireGuard := []byte{0x01, 0x01, 0x02, 0x03}

	addr1 := &net.UDPAddr{
		Port: 12345,
		IP:   net.ParseIP("127.0.0.1"),
	}

	addr2 := &net.UDPAddr{
		Port: 12345,
		IP:   net.ParseIP("::1"),
	}

	addr3 := &net.UDPAddr{
		Port: 12346,
		IP:   net.ParseIP("127.0.0.1"),
	}

	addr4 := &net.UDPAddr{
		Port: 12346,
		IP:   net.ParseIP("::1"),
	}

	addr5 := &net.UDPAddr{
		Port: 12345,
		IP:   net.ParseIP("127.0.0.123"),
	}

	t.Run("Valid Rosenpass packet to IPv4", func(t *testing.T) {
		test(t, true, dataRosenpass, addr1, addr1)
	})

	t.Run("Valid Rosenpass packet to IPv6", func(t *testing.T) {
		test(t, true, dataRosenpass, addr2, addr2)
	})

	t.Run("Non Rosenpass packet to IPv4", func(t *testing.T) {
		test(t, false, dataWireGuard, addr1, addr1)
	})

	t.Run("Non Rosenpass packet to IPv6", func(t *testing.T) {
		test(t, false, dataWireGuard, addr2, addr2)
	})

	t.Run("Rosenpass packet to different IPv4 port", func(t *testing.T) {
		test(t, false, dataWireGuard, addr1, addr3)
	})

	t.Run("Rosenpass packet to different IPv6 port", func(t *testing.T) {
		test(t, false, dataRosenpass, addr2, addr4)
	})

	t.Run("Rosenpass packet to IPv4 (again)", func(t *testing.T) {
		test(t, true, dataRosenpass, addr1, addr1)
	})

	t.Run("Rosenpass packet to IPv6 (again)", func(t *testing.T) {
		test(t, true, dataRosenpass, addr2, addr2)
	})

	t.Run("Rosenpass packet to IPv4 different IP", func(t *testing.T) {
		test(t, false, dataRosenpass, addr5, addr1)
	})

	t.Run("Listen on nil", func(t *testing.T) {
		require := require.New(t)

		_, err := netx.ListenRawUDP("udp", nil)
		require.Error(err)

		for _, netw := range []string{"udp4", "udp6"} {
			c4, err := netx.ListenRawUDP(netw, nil)
			require.NoError(err)

			addr, ok := c4.LocalAddr().(*net.UDPAddr)

			require.True(ok)
			require.True(addr.Port >= 1024)
			require.True(addr.Port < 1<<16)
			require.NotNil(addr.IP)

			switch netw {
			case "udp4":
				require.Equal(net.ParseIP("0.0.0.0"), addr.IP)
			case "udp6":
				require.Equal(net.IPv6unspecified, addr.IP)
			}
		}
	})

	t.Run("Listen twice one same port", func(t *testing.T) {
		require := require.New(t)

		data := []byte{1, 2, 3, 4}
		rAddr := &net.UDPAddr{
			Port: 1234,
			IP:   net.IPv6loopback,
		}
		lAddr := &net.UDPAddr{
			Port: rAddr.Port,
		}

		c1, err := netx.ListenRawUDP("udp6", lAddr)
		require.NoError(err)

		c2, err := netx.ListenRawUDP("udp6", lAddr)
		require.NoError(err)

		n, err := c1.WriteTo(data, rAddr)
		require.NoError(err)
		require.Len(data, n)

		for _, c := range []net.PacketConn{c1, c2} {
			buf := make([]byte, 500)
			n, rAddrRead, err := c.ReadFrom(buf)
			require.NoError(err)
			require.Len(data, n)
			require.Equal(data, buf[:n])
			require.Equal(rAddr, rAddrRead)
		}
	})
}
