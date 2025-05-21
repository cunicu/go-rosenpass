// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"cunicu.li/go-rosenpass/config"

	rp "cunicu.li/go-rosenpass"

	"github.com/spf13/cobra"
)

var errEitherConfigOrKeys = errors.New("either a config-file or both public-key and secret-key file are required")

func genKeyIntf(_ *cobra.Command, args []string) error {
	intfName := args[0]

	dir := filepath.Join("/etc/wireguard", intfName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to generate directory: %w", err)
	}

	pkPath := filepath.Join(dir, "pqpk")
	skPath := filepath.Join(dir, "pqsk")

	return doGenKeys(pkPath, skPath)
}

func genKey(_ *cobra.Command, args []string) error {
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
		return errEitherConfigOrKeys
	}

	return doGenKeys(pkPath, skPath)
}

func doGenKeys(pkPath, skPath string) error {
	if _, err := os.Stat(pkPath); err == nil && !force {
		return fmt.Errorf("public-key file \"%s\" exist, refusing to overwrite it", pkPath)
	}

	if _, err := os.Stat(skPath); err == nil && !force {
		return fmt.Errorf("secret-key file \"%s\" exist, refusing to overwrite it", skPath)
	}

	spk, ssk, err := rp.GenerateKeyPair()
	if err != nil {
		return err
	}

	if err := os.WriteFile(pkPath, spk[:], 0o600); err != nil {
		return fmt.Errorf("failed to write static public key: %w", err)
	}

	if err := os.WriteFile(skPath, ssk[:], 0o600); err != nil {
		return fmt.Errorf("failed to write static secret key: %w", err)
	}

	return nil
}
