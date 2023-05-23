// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass_test

import (
	"encoding/base64"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInteropKeygen(t *testing.T) {
	require := require.New(t)

	rp := &Rosenpass{}

	err := rp.Keygen()
	require.NoError(err)

	require.NotEmpty(rp.privateKey)
	require.NotEmpty(rp.publicKey)
}

func TestInteropRust2Rust(t *testing.T) {
	require := require.New(t)

	rp1 := &Rosenpass{
		Name:    "rp1",
		Verbose: true,
		ListenAddr: &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1100,
		},
	}

	rp2 := &Rosenpass{
		Name:    "rp2",
		Verbose: true,
		// ListenAddr: &net.UDPAddr{
		// 	IP:   net.ParseIP("127.0.0.1"),
		// 	Port: 1101,
		// },
	}

	require.NoError(rp1.Keygen())
	require.NoError(rp2.Keygen())

	pr1 := rp2.Peer()
	pr2 := rp1.Peer()

	pr1.Keys = make(chan []byte)
	pr2.Keys = make(chan []byte)

	rp1.Peers = append(rp1.Peers, pr1)
	rp2.Peers = append(rp2.Peers, pr2)

	ex1, err := rp1.Exchange()
	require.NoError(err)

	ex2, err := rp2.Exchange()
	require.NoError(err)

	go ex1.Start()
	// time.Sleep(500 * time.Millisecond)
	go ex2.Start()

	for i := 0; i < 2; i++ {
		psk1 := <-pr1.Keys
		psk2 := <-pr2.Keys

		require.Equal(psk1, psk2, "Keys differ in exchange %d", i)

		t.Logf("OSK: %s\n", base64.StdEncoding.EncodeToString(psk1))
	}

	require.NoError(ex1.Process.Signal(os.Interrupt))
	require.NoError(ex2.Process.Signal(os.Interrupt))

	ex1.Wait()
	ex2.Wait()
}
