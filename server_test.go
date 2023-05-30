// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass_test

import (
	"encoding/base64"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	rp "github.com/stv0g/go-rosenpass"
	"golang.org/x/exp/slog"
)

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

	psk, err := rp.GeneratePresharedKey()
	require.NoError(err)

	h1 := &handshakeHandler{
		keys: make(chan rp.Key),
	}
	h2 := &handshakeHandler{
		keys: make(chan rp.Key),
	}

	cfgAlice := rp.Config{
		Listen: &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		},
		Peers: []rp.PeerConfig{
			{
				PresharedKey: psk,
				Endpoint: &net.UDPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 1235,
				},
			},
		},
		Handlers: []rp.HandshakeHandler{
			h1,
		},
		Logger: slog.Default().With("peer", "alice"),
	}

	cfgBob := rp.Config{
		Listen: &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1235,
		},
		Peers: []rp.PeerConfig{
			{
				PresharedKey: psk,
				Endpoint: &net.UDPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 1234,
				},
			},
		},
		Handlers: []rp.HandshakeHandler{
			h2,
		},
		Logger: slog.Default().With("peer", "bob"),
	}

	cfgAlice.SecretKey, cfgAlice.PublicKey, err = rp.GenerateKeyPair()
	require.NoError(err)

	cfgBob.SecretKey, cfgBob.PublicKey, err = rp.GenerateKeyPair()
	require.NoError(err)

	cfgAlice.Peers[0].PublicKey = cfgBob.PublicKey
	cfgBob.Peers[0].PublicKey = cfgAlice.PublicKey

	svrAlice, err := rp.NewUDPServer(cfgAlice)
	require.NoError(err)
	require.NoError(svrAlice.Run())

	svrBob, err := rp.NewUDPServer(cfgBob)
	require.NoError(err)
	require.NoError(svrBob.Run())

	for i := 0; i < 1; i++ {
		psk1 := <-h1.keys
		psk2 := <-h2.keys

		require.Equal(psk1, psk2, "Keys differ in exchange %d", i)

		t.Logf("OSK: %s\n", base64.StdEncoding.EncodeToString(psk1[:]))
	}

	require.NoError(svrAlice.Close())
	require.NoError(svrBob.Close())
}
