// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slog"
)

type handshakeHandler struct {
	logger *slog.Logger
}

func (h *handshakeHandler) HandshakeCompleted(peer pid, osk key) {
	h.logger.Debug("Handshake completed", "osk", osk, "peer", peer)
}

func (h *handshakeHandler) HandshakeFailed(pid, error) {
}

func TestMain(m *testing.M) {
	textHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(textHandler)

	slog.SetDefault(logger)

	m.Run()
}

func TestServer(t *testing.T) {
	require := require.New(t)

	psk, err := GeneratePresharedKey()
	require.NoError(err)

	cfgAlice := Config{
		Listen: &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		},
		Peers: []PeerConfig{
			{
				PresharedKey: psk,
				Endpoint: &net.UDPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 1235,
				},
			},
		},
		Logger: slog.Default().With("peer", "alice"),
	}

	cfgBob := Config{
		Listen: &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1235,
		},
		Peers: []PeerConfig{
			{
				PresharedKey: psk,
				Endpoint: &net.UDPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 1234,
				},
			},
		},
		Logger: slog.Default().With("peer", "bob"),
	}

	cfgAlice.SecretKey, cfgAlice.PublicKey, err = generateKeyPair(kemAlgStatic)
	require.NoError(err)

	cfgBob.SecretKey, cfgBob.PublicKey, err = generateKeyPair(kemAlgStatic)
	require.NoError(err)

	cfgAlice.Peers[0].PublicKey = cfgBob.PublicKey
	cfgBob.Peers[0].PublicKey = cfgAlice.PublicKey

	svrAlice, err := NewUDPServer(cfgAlice)
	require.NoError(err)
	require.NoError(svrAlice.Run())

	svrBob, err := NewUDPServer(cfgBob)
	require.NoError(err)
	require.NoError(svrBob.Run())

	select {}

	require.NoError(svrAlice.Close())
	require.NoError(svrBob.Close())
}
