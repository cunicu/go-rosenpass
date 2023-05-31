// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass_test

import (
	"encoding/base64"
	"fmt"
	"math"
	"math/rand"
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
	run := func(t *testing.T, newGoServer, newRustServer func(*testing.T, string, rp.Config) (test.Server, error)) {
		testHandshake(t, newGoServer, newGoServer)

		t.Run("interop", func(t *testing.T) {
			t.Run("Rust to Go", func(t *testing.T) {
				testHandshake(t, newRustServer, newGoServer)
			})

			t.Run("Go to Rust", func(t *testing.T) {
				testHandshake(t, newGoServer, newRustServer)
			})
		})
	}

	t.Run("Rust", func(t *testing.T) {
		testHandshake(t, newStandaloneRustServer, newStandaloneRustServer)
	})

	t.Run("in-process", func(t *testing.T) {
		run(t, newGoServer, newStandaloneRustServer)
	})

	t.Run("standalone", func(t *testing.T) {
		run(t, newStandaloneGoServer, newStandaloneRustServer)
	})
}

func newGoServer(t *testing.T, name string, cfg rp.Config) (test.Server, error) {
	cfg.Logger = slog.Default().With("node", name)

	return rp.NewUDPServer(cfg)
}

func newStandaloneGoServer(t *testing.T, name string, cfg rp.Config) (test.Server, error) {
	executable, err := test.EnsureBuild(t)
	if err != nil {
		return nil, fmt.Errorf("failed to build go-rosenpass: %w", err)
	}

	dir := filepath.Join(t.TempDir(), name)

	cfg.Logger = slog.Default().With("node", name)

	return test.NewStandaloneServer(cfg, executable, dir)
}

func newStandaloneRustServer(t *testing.T, name string, cfg rp.Config) (test.Server, error) {
	dir := filepath.Join(t.TempDir(), name)

	cfg.Logger = slog.Default().With("node", name)

	return test.NewStandaloneServer(cfg, "rosenpass", dir)
}

func testHandshake(t *testing.T, newAlice, newBob func(*testing.T, string, rp.Config) (test.Server, error)) {
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

	portAlice := int(1024 + rand.Int31n(math.MaxUint16-1024))
	portBob := int(1024 + rand.Int31n(math.MaxUint16-1024))

	cfgAlice := rp.Config{
		PublicKey: publicKeyAlice,
		SecretKey: secretKeyAlice,
		Listen: &net.UDPAddr{
			IP:   net.IPv6loopback,
			Port: portAlice,
		},
		Peers: []rp.PeerConfig{
			{
				PresharedKey: psk,
				Endpoint: &net.UDPAddr{
					IP:   net.IPv6loopback,
					Port: portBob,
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
			Port: portBob,
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
	svrAlice, err := newAlice(t, "alice", cfgAlice)
	require.NoError(err)

	svrBob, err := newBob(t, "bob", cfgBob)
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
