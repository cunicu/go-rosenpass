// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/stv0g/go-rosenpass/config"
)

func genConfig(cmd *cobra.Command, args []string) error {
	cfgFilename := args[0]

	if _, err := os.Stat(cfgFilename); err == nil && !force {
		return fmt.Errorf("config file \"%s\" already exists", cfgFilename)
	}

	ep := "my-peer.test:9999"
	ko := "rp-key-out"

	cfgFile := config.File{
		PublicKey: "rp-public-key",
		SecretKey: "rp-secret-key",
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
			},
		},
	}

	return cfgFile.DumpFile(cfgFilename)
}
