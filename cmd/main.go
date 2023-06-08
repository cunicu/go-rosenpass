// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
)

var (
	logger                     *slog.Logger
	skPath, pkPath, configFile string
	verbose, force             bool
)

func main() {
	logger = slog.New(slog.NewTextHandler(os.Stderr, nil))

	rootCmd := &cobra.Command{
		Use:           "rosepass",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a configuration",
		RunE:  validate,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			setupLogging(verbose)
		},
	}

	genKeyCmd := &cobra.Command{
		Use:   "gen-keys",
		Short: "Generate a keypair to use in the exchange command later.",
		Long:  "Send the public-key file to your communication partner and keep the secret-key file a secret!",
		Args:  cobra.MaximumNArgs(1),
		RunE:  genKey,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			setupLogging(verbose)
		},
	}

	f := genKeyCmd.PersistentFlags()
	f.StringVarP(&pkPath, "public-key", "p", "", "where to write public-key to")
	f.StringVarP(&skPath, "secret-key", "s", "", "where to write secret-key to")
	f.BoolVarP(&force, "force", "f", false, "Forcefully overwrite public- & secret-key file")

	genConfigCmd := &cobra.Command{
		Use:   "gen-config config-file",
		Short: "Generate a demo config file",
		Args:  cobra.ExactArgs(1),
		RunE:  genConfig,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			setupLogging(verbose)
		},
	}

	f = genConfigCmd.PersistentFlags()
	f.BoolVarP(&force, "force", "f", false, "Forcefully overwrite existing config file")

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
	rootCmd.AddCommand(genConfigCmd)
	rootCmd.AddCommand(exchangeConfigCmd)
	rootCmd.AddCommand(exchangeCmd)
	rootCmd.AddCommand(validateCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.Error("Error", slog.Any("error", err))
		os.Exit(-1)
	}
}

func setupLogging(verbose bool) {
	opts := &slog.HandlerOptions{}

	if verbose {
		opts.Level = slog.LevelDebug
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	logger = slog.New(handler)
	slog.SetDefault(logger)
}
