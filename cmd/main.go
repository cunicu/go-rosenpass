// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/spf13/cobra"
	rp "github.com/stv0g/go-rosenpass"
)

func main() {
	rootCmd := &cobra.Command{
		Use: "rosepass",
	}

	keygenCmd := &cobra.Command{
		Use:   "keygen private-key public-key",
		Short: "Generate a keypair to use in the exchange command later.",
		Long:  "Send the public-key file to your communication partner and keep the private-key file a secret!",
		Args:  cobra.ExactArgs(2),
		RunE:  keygen,
	}

	rootCmd.AddCommand(keygenCmd)

	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}

func keygen(cmd *cobra.Command, args []string) error {
	skPath := args[0]
	pkPath := args[1]

	ssk, spk, err := rp.GenerateKeyPair()
	if err != nil {
		return err
	}

	if err := os.WriteFile(pkPath, spk[:], 0o644); err != nil {
		return err
	}

	if err := os.WriteFile(skPath, ssk[:], 0o600); err != nil {
		return err
	}

	return nil
}
