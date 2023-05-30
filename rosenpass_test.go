// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass_test

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	rp "github.com/stv0g/go-rosenpass"
	"github.com/stv0g/go-rosenpass/config"
)

const rosenpassExecutable = "rosenpass"

type Rosenpass struct {
	rp.Config

	Name string
	Dir  string
}

func (rp *Rosenpass) Exchange(t *testing.T, subDir string) *exec.Cmd {
	require := require.New(t)

	c := exec.Command(rosenpassExecutable)

	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	cfgDir := t.TempDir()
	if subDir != "" {
		cfgDir = filepath.Join(cfgDir, subDir)
	}

	err := os.MkdirAll(cfgDir, 0o755)
	require.NoError(err)

	cfgFile := config.File{}
	err = cfgFile.FromConfig(rp.Config, cfgDir)
	require.NoError(err)

	cfgFileName := filepath.Join(cfgDir, "config.toml")

	err = cfgFile.DumpFile(cfgFileName)
	require.NoError(err)

	c.Args = append(c.Args, "exchange-config", cfgFileName)

	log.Printf("Starting rosenpass %s", strings.Join(c.Args, " "))

	return c
}
