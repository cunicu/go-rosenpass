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

	_, spk, err := generateKeyPair(kemAlgStatic)
	require.NoError(err)

	p := &peer{
		spkt: spk,
		initialEndpoint: &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		},
	}

	c, err := newUDPConn(&net.UDPAddr{
		Port: 1234,
	})
	require.NoError(err)

	sid, err := generateSessionID()
	require.NoError(err)

	pls := make(chan payload)
	go func() {
		pl, _, err := c.Receive(spk)
		require.NoError(err)

		pls <- pl
	}()

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
