// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

var executable string

func EnsureBuild(t *testing.T) (string, error) {
	if executable == "" {
		outputDir := t.TempDir()
		output := filepath.Join(outputDir, "go-rosenpass")

		c := exec.Command("go", "build", "-o", output, "./cmd")
		c.Stderr = os.Stderr
		c.Stdout = os.Stdout

		if err := c.Run(); err != nil {
			return "", err
		}

		executable = output
	}

	return executable, nil
}
