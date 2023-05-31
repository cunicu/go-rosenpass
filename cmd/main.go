// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	rp "github.com/stv0g/go-rosenpass"
	"github.com/stv0g/go-rosenpass/config"
	"golang.org/x/exp/slog"
)

var (
	logger                     *slog.Logger
	skPath, pkPath, configFile string
	verbose                    bool
)

func main() {
	logger = slog.New(slog.NewTextHandler(os.Stderr, nil))

	rootCmd := &cobra.Command{
		Use:              "rosepass",
		PersistentPreRun: setupLogging,
		SilenceUsage:     true,
	}

	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a configuration",
		RunE:  validate,
	}

	genKeyCmd := &cobra.Command{
		Use:   "gen-keys",
		Short: "Generate a keypair to use in the exchange command later.",
		Long:  "Send the public-key file to your communication partner and keep the secret-key file a secret!",
		Args:  cobra.MaximumNArgs(1),
		RunE:  genKey,
	}

	f := genKeyCmd.PersistentFlags()
	f.StringVarP(&pkPath, "public-key", "p", "", "where to write public-key to")
	f.StringVarP(&skPath, "secret-key", "s", "", "where to write secret-key to")

	exchangeConfigCmd := &cobra.Command{
		Use:   "exchange-config config-file",
		Short: "Start Rosenpass in server mode and carry on with the key exchange",
		Long:  "This will parse the configuration file and perform the key exchange with the specified peers. If a peer's endpoint is specified, this Rosenpass instance will try to initiate a key exchange with the peer, otherwise only initiation attempts from the peer will be responded to.",
		Args:  cobra.ExactArgs(1),
		RunE:  exchangeConfig,
	}

	exchangeCmd := &cobra.Command{
		Use:   "exchange public-key <PATH> secret-key <PATH> [listen <ADDR>:<PORT>]... [verbose] [peer] [public-key] [<PATH>] [[ENDPOINT]] [[PSK]] [[OUTFILE]] [[WG]]...",
		Short: "Start Rosenpass in server mode and carry on with the key exchange",
		Long:  "This will parse the configuration file and perform the key exchange with the specified peers. If a peer's endpoint is specified, this Rosenpass instance will try to initiate a key exchange with the peer, otherwise only initiation attempts from the peer will be responded to.",
		RunE:  exchange,
	}

	f = exchangeCmd.PersistentFlags()
	f.StringVarP(&configFile, "config-file", "c", "", "Save the parsed configuration to a file before starting the daemon")

	f = rootCmd.PersistentFlags()
	f.BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")

	rootCmd.AddCommand(genKeyCmd)
	rootCmd.AddCommand(exchangeConfigCmd)
	rootCmd.AddCommand(exchangeCmd)
	rootCmd.AddCommand(validateCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.Error("Error", slog.Any("error", err))
		os.Exit(-1)
	}
}

func setupLogging(cmd *cobra.Command, args []string) {
	opts := &slog.HandlerOptions{}

	if verbose {
		opts.Level = slog.LevelDebug
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	logger = slog.New(handler)
}

func validate(cmd *cobra.Command, args []string) error {
	errors := 0
	for _, cfgFilename := range args {
		cfgFile := config.File{}

		if err := cfgFile.LoadFile(cfgFilename); err != nil {
			errors++
			logger.Error("Failed to load config file", slog.String("file", cfgFilename), slog.Any("error", err))
		}

		if _, err := cfgFile.ToConfig(); err != nil {
			errors++
			logger.Error("Failed to parse config file", slog.String("file", cfgFilename), slog.Any("error", err))
		}
	}

	if errors > 0 {
		return fmt.Errorf("found %d errors", errors)
	}

	return nil
}

func genKey(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		cfgFilename := args[0]
		cfgFile := config.File{}

		if err := cfgFile.LoadFile(cfgFilename); err != nil {
			return fmt.Errorf("failed to load config file: %w", err)
		}

		pkPath = cfgFile.PublicKey
		skPath = cfgFile.SecretKey
	}

	if pkPath == "" || skPath == "" {
		return errors.New("Either a config-file or both public-key and secret-key file are required")
	}

	if _, err := os.Stat(pkPath); err == nil {
		return fmt.Errorf("public-key file \"%s\" exist, refusing to overwrite it", pkPath)
	}

	if _, err := os.Stat(skPath); err == nil {
		return fmt.Errorf("secret-key file \"%s\" exist, refusing to overwrite it", skPath)
	}

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
	cfg, err := rp.ConfigFromArgs(args)
	if err != nil {
		return fmt.Errorf("failed to parse arguments: %s", err)
	}

	return doExchange(cfg)
}

func exchangeConfig(cmd *cobra.Command, args []string) error {
	cfgFilename := args[0]
	var cfgFile config.File

	if err := cfgFile.LoadFile(cfgFilename); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	cfg, err := cfgFile.ToConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	return doExchange(cfg)
}

func doExchange(cfg rp.Config) error {
	svr, err := rp.NewUDPServer(cfg)
	if err != nil {
		return err
	}

	if err := svr.Run(); err != nil {
		return err
	}

	// TODO: Register signal handler and shutdown server
	select {}
}
