// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	rp "github.com/stv0g/go-rosenpass"
	"github.com/stv0g/go-rosenpass/config"
)

func genConfig(_ *cobra.Command, args []string) error {
	cfgFilename := args[0]

	if _, err := os.Stat(cfgFilename); err == nil && !force {
		return fmt.Errorf("config file \"%s\" already exists", cfgFilename)
	}

	ep := "my-peer.test:9999"
	ko := "rp-key-out"

	pk, err := rp.GeneratePresharedKey()
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	pskFile := "rp-peer-preshared-key"

	cfgFile := config.File{
		PublicKey: "rp-public-key",
		SecretKey: "rp-secret-key",
		Verbosity: "Verbose",
		ListenAddrs: []string{
			"192.0.2.22:15122",
			"[2001:0db8:85a3::8a2e:0370:7334]:25223",
			"0.0.0.0:1234",
			"[::]:1234",
		},
		Peers: []config.PeerSection{
			{
				PublicKey: "rp-peer-public-key",
				Endpoint:  &ep,
				KeyOut:    &ko,
				ExchangeCommand: []string{
					"wg",
					"set",
					"wg0",
					"peer",
					"<PEER_ID>",
					"preshared-key",
					"/dev/stdin",
				},
				PresharedKey: &pskFile,
				WireGuard: &config.WireGuardSection{
					Interface: "wg0",
					PublicKey: pk,
				},
			},
		},
	}

	return cfgFile.DumpFile(cfgFilename)
}
