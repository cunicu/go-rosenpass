// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	rp "github.com/stv0g/go-rosenpass"
	"github.com/stv0g/go-rosenpass/config"
	"golang.org/x/exp/slog"
)

var skPath, pkPath string

func main() {
	rootCmd := &cobra.Command{
		Use: "rosepass",
	}

	keygenCmd := &cobra.Command{
		Use:   "keygen secret-key public-key",
		Short: "Generate a keypair to use in the exchange command later.",
		Long:  "Send the public-key file to your communication partner and keep the secret-key file a secret!",
		Args:  cobra.ExactArgs(2),
		RunE:  keygen,
	}

	f := keygenCmd.Flags()
	f.StringVarP(&pkPath, "public-key", "p", "", "where to write public-key to")
	f.StringVarP(&pkPath, "secret-key", "s", "", "where to write secret-key to")

	exchangeCmd := &cobra.Command{
		Use:   "exchange-config config-file",
		Short: "Start Rosenpass in server mode and carry on with the key exchange",
		Long:  "This will parse the configuration file and perform the key exchange with the specified peers. If a peer's endpoint is specified, this Rosenpass instance will try to initiate a key exchange with the peer, otherwise only initiation attempts from the peer will be responded to.",
		Args:  cobra.ExactArgs(1),
		RunE:  exchange,
	}

	rootCmd.AddCommand(keygenCmd)
	rootCmd.AddCommand(exchangeCmd)

	textHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(textHandler)

	slog.SetDefault(logger)

	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}

func keygen(cmd *cobra.Command, args []string) error {
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

func exchange(cmd *cobra.Command, args []string) error {
	cfgFilename := args[0]
	var cfgFile config.File

	if err := cfgFile.LoadFile(cfgFilename); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	cfg, err := cfgFile.ToConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	svr, err := rp.NewUDPServer(cfg)
	if err != nil {
		return err
	}

	if err := svr.Run(); err != nil {
		return err
	}

	select {}
}
