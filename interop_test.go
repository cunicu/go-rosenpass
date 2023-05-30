// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass_test

import (
	"encoding/base64"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	rp "github.com/stv0g/go-rosenpass"
)

type handshakeHandler struct {
	keys chan rp.Key
}

func (h *handshakeHandler) HandshakeCompleted(pid rp.PeerID, key rp.Key) {
	h.keys <- key
}

func TestInteropRust2Rust(t *testing.T) {
	require := require.New(t)

	ssk1, spk1, err := rp.GenerateKeyPair()
	require.NoError(err)

	ssk2, spk2, err := rp.GenerateKeyPair()
	require.NoError(err)

	h1 := &handshakeHandler{
		keys: make(chan rp.Key),
	}

	h2 := &handshakeHandler{
		keys: make(chan rp.Key),
	}

	rp1 := &Rosenpass{
		Name: "rp1",
		Config: rp.Config{
			Handlers:  []rp.HandshakeHandler{h1},
			PublicKey: spk1,
			SecretKey: ssk1,
			Listen: &net.UDPAddr{
				IP:   net.ParseIP("127.0.0.1"),
				Port: 1100,
			},
		},
	}

	rp2 := &Rosenpass{
		Name: "rp2",
		Config: rp.Config{
			Handlers:  []rp.HandshakeHandler{h2},
			PublicKey: spk2,
			SecretKey: ssk2,
			Listen: &net.UDPAddr{
				IP:   net.ParseIP("127.0.0.1"),
				Port: 1101,
			},
		},
	}

	pr1 := rp2.PeerConfig()
	pr2 := rp1.PeerConfig()

	rp1.Peers = append(rp1.Peers, pr1)
	rp2.Peers = append(rp2.Peers, pr2)

	ex1 := rp1.Exchange(t, "1")
	require.NoError(err)

	ex2 := rp2.Exchange(t, "2")
	require.NoError(err)

	go func() {
		err := ex1.Start()
		require.NoError(err)
	}()
	time.Sleep(1000 * time.Millisecond)
	go func() {
		err := ex2.Start()
		require.NoError(err)
	}()

	for i := 0; i < 2; i++ {
		psk1 := <-h1.keys
		psk2 := <-h2.keys

		require.Equal(psk1, psk2, "Keys differ in exchange %d", i)

		t.Logf("OSK: %s\n", base64.StdEncoding.EncodeToString(psk1[:]))
	}

	require.NoError(ex1.Process.Signal(os.Interrupt))
	require.NoError(ex2.Process.Signal(os.Interrupt))

	err = ex1.Wait()
	require.NotErrorIs(err, &exec.ExitError{})

	err = ex2.Wait()
	require.NotErrorIs(err, &exec.ExitError{})
}
