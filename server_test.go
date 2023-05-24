// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	require := require.New(t)

	spkt, err := os.ReadFile("spkt.key")
	require.NoError(err)

	cfg := &ServerConfig{
		Listen: &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		},
		Peers: []PeerConfig{
			{
				PublicKey: spk(spkt),
				Endpoint: &net.UDPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 1235,
				},
			},
		},
	}

	cfg.PrivateKey, cfg.PublicKey, err = generateKeyPair(kemAlgStatic)
	require.NoError(err)

	s, err := NewServer(cfg)
	require.NoError(err)
	require.NoError(s.Run())
	require.NoError(s.Close())
}
