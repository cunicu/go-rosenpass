// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/spf13/cobra"
	rp "github.com/stv0g/go-rosenpass"
	"github.com/stv0g/go-rosenpass/config"
)

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
