// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass_test

import (
	"encoding/base64"
	"log/slog"
	"math"
	"math/rand"
	"net"
	"path/filepath"
	"testing"

	"cunicu.li/go-rosenpass/internal/test"

	rp "cunicu.li/go-rosenpass"

	"github.com/stretchr/testify/require"
)

type handshakeHandler struct {
	keys    chan rp.Key
	expired chan rp.PeerID
}

func (h *handshakeHandler) HandshakeCompleted(_ rp.PeerID, key rp.Key) {
	h.keys <- key
}

func (h *handshakeHandler) HandshakeExpired(pid rp.PeerID) {
	h.expired <- pid
}

func TestServer(t *testing.T) {
	t.Run("Rust-to-Rust", func(t *testing.T) {
		// We only perform a single handshake as the tests should not wait for the hardcoded rekey timeout
		testHandshake(t, newStandaloneRustServer, newStandaloneRustServer, rp.GenerateRound2KeyPair, rp.GenerateRound2KeyPair, 1)
	})

	t.Run("In-process", func(t *testing.T) {
		testInterop(t, newGoServer, newStandaloneRustServer, 4)
	})

	t.Run("Standalone", func(t *testing.T) {
		testInterop(t, newStandaloneGoServer, newStandaloneRustServer, 1)
	})

	t.Run("Singleport", func(t *testing.T) {
		testHandshake(t, newSinglePortGoServer, newSinglePortGoServer, rp.GenerateKeyPair, rp.GenerateKeyPair, 1)
	})
}

func newSinglePortGoServer(t *testing.T, name string, cfg rp.Config) (test.Server, error) {
	cfg.ListenSinglePort = true
	return newGoServer(t, name, cfg)
}

func newGoServer(_ *testing.T, name string, cfg rp.Config) (test.Server, error) {
	cfg.Logger = slog.Default().With("node", name)

	return rp.NewUDPServer(cfg)
}

func newStandaloneGoServer(t *testing.T, name string, cfg rp.Config) (test.Server, error) {
	dir := filepath.Join(t.TempDir(), name)

	cfg.Logger = slog.Default().With("node", name)

	return test.NewStandaloneGoServer(cfg, dir)
}

func newStandaloneRustServer(t *testing.T, name string, cfg rp.Config) (test.Server, error) {
	dir := filepath.Join(t.TempDir(), name)

	cfg.Logger = slog.Default().With("node", name)

	return test.NewStandaloneServer(cfg, "rosenpass", dir)
}

func testInterop(t *testing.T, newGoServer, newRustServer func(*testing.T, string, rp.Config) (test.Server, error), numHandshakes int) {
	t.Run("Go-to-Go", func(t *testing.T) {
		testHandshake(t, newGoServer, newGoServer, rp.GenerateKeyPair, rp.GenerateKeyPair, numHandshakes)
	})

	t.Run("Rust-to-Go", func(t *testing.T) {
		testHandshake(t, newRustServer, newGoServer, rp.GenerateRound2KeyPair, rp.GenerateKeyPair, numHandshakes)
	})

	t.Run("Go-to-Rust", func(t *testing.T) {
		testHandshake(t, newGoServer, newRustServer, rp.GenerateKeyPair, rp.GenerateRound2KeyPair, numHandshakes)
	})
}

func testHandshake(t *testing.T, newServerAlice, newServerBob func(*testing.T, string, rp.Config) (test.Server, error), newKeyPairAlice, newKeyPairBob func() (rp.PublicKey, rp.SecretKey, error), numHandshakes int) {
	require := require.New(t)

	// Generate keys
	psk, err := rp.GeneratePresharedKey()
	require.NoError(err)

	publicKeyAlice, secretKeyAlice, err := newKeyPairAlice()
	require.NoError(err)

	publicKeyBob, secretKeyBob, err := newKeyPairBob()
	require.NoError(err)

	// Generate configurations
	handlerAlice := &handshakeHandler{
		keys:    make(chan rp.Key, 16),
		expired: make(chan rp.PeerID, 16),
	}

	handlerBob := &handshakeHandler{
		keys:    make(chan rp.Key, 16),
		expired: make(chan rp.PeerID, 16),
	}

	portAlice := int(1024 + rand.Int31n(math.MaxUint16-1024)) //nolint:gosec
	portBob := int(1024 + rand.Int31n(math.MaxUint16-1024))   //nolint:gosec

	cfgAlice := rp.Config{
		PublicKey: publicKeyAlice,
		SecretKey: secretKeyAlice,
		ListenAddrs: []*net.UDPAddr{
			{
				IP:   net.IPv6loopback,
				Port: portAlice,
			},
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
		Handlers: []rp.Handler{
			handlerAlice,
		},
	}

	cfgBob := rp.Config{
		PublicKey: publicKeyBob,
		SecretKey: secretKeyBob,
		ListenAddrs: []*net.UDPAddr{
			{
				IP:   net.IPv6loopback,
				Port: portBob,
			},
		},
		Peers: []rp.PeerConfig{
			{
				PresharedKey: psk,
				// Bob should be responder
				// so we dont specify and endpoint for Alice
			},
		},
		Handlers: []rp.Handler{
			handlerBob,
		},
	}

	cfgAlice.Peers[0].PublicKey = cfgBob.PublicKey
	cfgBob.Peers[0].PublicKey = cfgAlice.PublicKey

	// Create servers
	svrAlice, err := newServerAlice(t, "alice", cfgAlice)
	require.NoError(err)

	svrBob, err := newServerBob(t, "bob", cfgBob)
	require.NoError(err)

	err = svrAlice.Run()
	require.NoError(err)

	err = svrBob.Run()
	require.NoError(err)

	for i := 0; i < numHandshakes; i++ {
		oskAlice := <-handlerAlice.keys
		oskBob := <-handlerBob.keys

		require.Equal(oskAlice, oskBob, "Keys differ in exchange %d", i)

		t.Logf("OSK: %s\n", base64.StdEncoding.EncodeToString(oskAlice[:]))
	}

	// HandshakeExpiredHandlers are only supported for non-standalone servers
	if _, ok := svrAlice.(*rp.Server); ok {
		err = svrBob.Close()
		require.NoError(err)

		expired := <-handlerAlice.expired
		require.Equal(expired, cfgAlice.Peers[0].PID())

		require.NoError(svrAlice.Close())
	} else {
		require.NoError(svrAlice.Close())
		require.NoError(svrBob.Close())
	}
}
