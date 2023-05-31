// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"os"
	"os/exec"
)

var executable string

func EnsureBuild(coverPkg string) (string, error) {
	if executable == "" {
		output := "./go-rosenpass"

		c := exec.Command("go", "build", "-o", output)

		if coverPkg != "" {
			c.Args = append(c.Args, "-coverpkg", coverPkg)
		}

		c.Args = append(c.Args, "./cmd")
		c.Stderr = os.Stderr
		c.Stdout = os.Stdout

		if err := c.Run(); err != nil {
			return "", err
		}

		executable = output
	}

	return executable, nil
}
