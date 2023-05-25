// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass_test

import (
	"log"
	"os"
	"os/exec"
	"strings"

	rp "github.com/stv0g/go-rosenpass"
	"github.com/stv0g/go-rosenpass/config"
)

const rosenpassExecutable = "rosenpass"

type Rosenpass struct {
	rp.Config

	Name string
}

func (rp *Rosenpass) Exchange() (*exec.Cmd, error) {
	c := exec.Command("cat")

	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	_, err := config.NewConfigPipe(rp.Config, c)
	if err != nil {
		return nil, err
	}

	// c.Args = append(c.Args, "exchange-config", fn)
	c.Args = append(c.Args, "/dev/fd3")

	log.Printf("Starting rosenpass %s", strings.Join(c.Args, " "))

	return c, nil
}
