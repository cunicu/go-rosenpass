// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/stv0g/go-rosenpass/config"
	"golang.org/x/exp/slog"
)

func validate(_ *cobra.Command, args []string) error {
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
