// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass_test

import (
	"encoding/base64"
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	rp "github.com/stv0g/go-rosenpass"
	"github.com/stv0g/go-rosenpass/internal/test"
	"golang.org/x/exp/slog"
)

type handshakeHandler struct {
	keys chan rp.Key
}

func (h *handshakeHandler) HandshakeCompleted(pid rp.PeerID, key rp.Key) {
	h.keys <- key
}

func TestServer(t *testing.T) {
	newRustServer := func(name string, cfg rp.Config) (test.Server, error) {
		dir := filepath.Join(t.TempDir(), name)

		cfg.Logger = slog.Default().With("node", name)

		return test.NewRustServer(cfg, dir)
	}

	newGolangServer := func(name string, cfg rp.Config) (test.Server, error) {
		cfg.Logger = slog.Default().With("node", name)

		return rp.NewUDPServer(cfg)
	}

	t.Run("Rust to Rust", func(t *testing.T) {
		testServer(t, newRustServer, newRustServer)
	})

	t.Run("Go to Go", func(t *testing.T) {
		testServer(t, newGolangServer, newGolangServer)
	})

	t.Run("Rust to Go", func(t *testing.T) {
		testServer(t, newRustServer, newGolangServer)
	})

	t.Run("Go to Rust", func(t *testing.T) {
		testServer(t, newGolangServer, newRustServer)
	})
}

func testServer(t *testing.T, newAlice, newBob func(string, rp.Config) (test.Server, error)) {
	require := require.New(t)

	// Generate keys
	psk, err := rp.GeneratePresharedKey()
	require.NoError(err)

	secretKeyAlice, publicKeyAlice, err := rp.GenerateKeyPair()
	require.NoError(err)

	secretKeyBob, publicKeyBob, err := rp.GenerateKeyPair()
	require.NoError(err)

	// Generate configurations
	handlerAlice := &handshakeHandler{
		keys: make(chan rp.Key, 2),
	}

	handlerBob := &handshakeHandler{
		keys: make(chan rp.Key, 2),
	}

	cfgAlice := rp.Config{
		PublicKey: publicKeyAlice,
		SecretKey: secretKeyAlice,
		Listen: &net.UDPAddr{
			IP:   net.IPv6loopback,
			Port: 1234,
		},
		Peers: []rp.PeerConfig{
			{
				PresharedKey: psk,
				Endpoint: &net.UDPAddr{
					IP:   net.IPv6loopback,
					Port: 1235,
				},
			},
		},
		Handlers: []rp.HandshakeHandler{
			handlerAlice,
		},
	}

	cfgBob := rp.Config{
		PublicKey: publicKeyBob,
		SecretKey: secretKeyBob,
		Listen: &net.UDPAddr{
			IP:   net.IPv6loopback,
			Port: 1235,
		},
		Peers: []rp.PeerConfig{
			{
				PresharedKey: psk,
				// Bob should be responder
				// so we dont specify and endpoint for Alice
			},
		},
		Handlers: []rp.HandshakeHandler{
			handlerBob,
		},
	}

	cfgAlice.Peers[0].PublicKey = cfgBob.PublicKey
	cfgBob.Peers[0].PublicKey = cfgAlice.PublicKey

	// Create servers
	svrAlice, err := newAlice("alice", cfgAlice)
	require.NoError(err)

	svrBob, err := newBob("bob", cfgBob)
	require.NoError(err)

	err = svrAlice.Run()
	require.NoError(err)

	err = svrBob.Run()
	require.NoError(err)

	for i := 0; i < 1; i++ {
		oskAlice := <-handlerAlice.keys
		oskBob := <-handlerBob.keys

		require.Equal(oskAlice, oskBob, "Keys differ in exchange %d", i)

		t.Logf("OSK: %s\n", base64.StdEncoding.EncodeToString(oskAlice[:]))
	}

	require.NoError(svrAlice.Close())
	require.NoError(svrBob.Close())
}
