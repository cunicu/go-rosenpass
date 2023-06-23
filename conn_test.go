// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUDPConn(t *testing.T) {
	require := require.New(t)

	spk, _, err := generateStaticKeyPair()
	require.NoError(err)

	p := &peer{
		spkt: spk,
		endpoint: &net.UDPAddr{
			IP:   net.IPv6loopback,
			Port: 1234,
		},
	}

	c, err := newUDPConn([]*net.UDPAddr{
		{
			Port: 1234,
		},
	})
	require.NoError(err)

	sid, err := generateSessionID()
	require.NoError(err)

	recvFncs, err := c.Open()
	require.NoError(err)

	pls := make(chan payload)
	for _, recvFnc := range recvFncs {
		go func(recvFnc receiveFunc) {
			pl, _, err := recvFnc(spk)
			require.NoError(err)

			pls <- pl
		}(recvFnc)
	}

	eds := &emptyData{
		sid: sid,
	}

	err = c.Send(eds, p)
	require.NoError(err)

	edr := <-pls
	require.Equal(edr, eds)

	err = c.Close()
	require.NoError(err)
}
