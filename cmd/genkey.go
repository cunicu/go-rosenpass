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
)

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

	spk, ssk, err := rp.GenerateKeyPair()
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
