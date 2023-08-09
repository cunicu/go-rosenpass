// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var (
	skPath, pkPath, configFile string
	verbose, force             bool

	genManOpts = doc.GenManTreeOptions{
		CommandSeparator: "-",
		Header: &doc.GenManHeader{
			Source: "https://github.com/stv0g/go-rosenpass",
		},
	}

	rootCmd = &cobra.Command{
		Use:           "go-rosenpass",
		Short:         "Rosenpass is a formally verified, post-quantum secure VPN that uses WireGuard to transport the actual data.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			setupLogging(verbose)
		},
	}

	manCmd = &cobra.Command{
		Use:   "man",
		Short: "Show the go-rosenpass manpage",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			page := strings.Join(append([]string{"go-rosenpass"}, args...), genManOpts.CommandSeparator)
			c := exec.Command("man", "1", page)
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			return c.Run()
		},
	}

	validateCmd = &cobra.Command{
		Use:   "validate [flags] config-files...",
		Short: "Validate a configuration",
		RunE:  validate,
	}

	genKeyCmd = &cobra.Command{
		Use:   "gen-keys [flags]  [config-file]",
		Short: "Generate a keypair to use in the exchange command later.",
		Long:  "Send the public-key file to your communication partner and keep the secret-key file a secret!",
		Args:  cobra.MaximumNArgs(1),
		RunE:  genKey,
	}

	genManCmd = &cobra.Command{
		Use:   "gen-man",
		Short: "Generate man pages",
		Args:  cobra.NoArgs,
		RunE:  genMan,
	}

	genConfigCmd = &cobra.Command{
		Use:   "gen-config [flags] config-file",
		Short: "Generate a demo config file",
		Args:  cobra.ExactArgs(1),
		RunE:  genConfig,
	}

	exchangeConfigCmd = &cobra.Command{
		Use:   "exchange-config [flags] config-file",
		Short: "Start Rosenpass in server mode and carry on with the key exchange",
		Long:  "This will parse the configuration file and perform the key exchange with the specified peers. If a peer's endpoint is specified, this Rosenpass instance will try to initiate a key exchange with the peer, otherwise only initiation attempts from the peer will be responded to.",
		Args:  cobra.ExactArgs(1),
		RunE:  exchangeConfig,
	}

	exchangeCmd = &cobra.Command{
		Use:   "exchange public-key <PATH> secret-key <PATH> [listen <ADDR>:<PORT>]... [verbose] [peer] [public-key] [<PATH>] [[ENDPOINT]] [[PSK]] [[OUTFILE]] [[WG]]...",
		Short: "Start in daemon mode, performing key exchanges",
		Long:  "This will parse the configuration file and perform the key exchange with the specified peers. If a peer's endpoint is specified, this Rosenpass instance will try to initiate a key exchange with the peer, otherwise only initiation attempts from the peer will be responded to.",
		RunE:  exchange,
	}
)

func main() {
	setupLogging(false)

	f := genKeyCmd.PersistentFlags()
	f.StringVarP(&pkPath, "public-key", "p", "", "where to write public-key to")
	f.StringVarP(&skPath, "secret-key", "s", "", "where to write secret-key to")
	f.BoolVarP(&force, "force", "f", false, "Forcefully overwrite public- & secret-key file")

	f = genManCmd.PersistentFlags()
	f.StringVarP(&genManOpts.Path, "path", "p", "/usr/local/share/man/man1", "path to the man directory")

	f = genConfigCmd.PersistentFlags()
	f.BoolVarP(&force, "force", "f", false, "forcefully overwrite existing config file")

	f = exchangeCmd.PersistentFlags()
	f.StringVarP(&configFile, "config-file", "c", "", "save the parsed configuration to a file before starting the daemon")

	f = rootCmd.PersistentFlags()
	f.BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")

	rootCmd.AddCommand(genKeyCmd)
	rootCmd.AddCommand(genConfigCmd)
	rootCmd.AddCommand(genManCmd)
	rootCmd.AddCommand(exchangeConfigCmd)
	rootCmd.AddCommand(exchangeCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(manCmd)

	if err := rootCmd.Execute(); err != nil {
		slog.Error("Error", slog.Any("error", err))
		os.Exit(-1) //nolint:forbidigo // This is the only occurrence in the code
	}
}

func setupLogging(verbose bool) {
	opts := &slog.HandlerOptions{}

	if verbose {
		opts.Level = slog.LevelDebug
	}

	handler := slog.NewTextHandler(os.Stderr, opts)
	logger := slog.New(handler)

	slog.SetDefault(logger)
}
