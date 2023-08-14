// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"cunicu.li/go-rosenpass/config"

	rp "cunicu.li/go-rosenpass"

	"github.com/spf13/cobra"
)

func exchange(_ *cobra.Command, args []string) error {
	_, cfgFile, err := config.FromArgs(args)
	if err != nil {
		return fmt.Errorf("failed to parse arguments: %s", err)
	}

	if cfgFile.Verbosity != "" {
		setupLogging(cfgFile.Verbosity == "Verbose")
	}

	return doExchange(cfgFile)
}

func exchangeConfig(_ *cobra.Command, args []string) error {
	cfgFilename := args[0]
	var cfgFile config.File

	if err := cfgFile.LoadFile(cfgFilename); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfgFile.Verbosity != "" {
		setupLogging(cfgFile.Verbosity == "Verbose")
	}

	return doExchange(cfgFile)
}

func doExchange(cfgFile config.File) error {
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

	// TODO: Register signal handler and shutdown server
	select {}
}
