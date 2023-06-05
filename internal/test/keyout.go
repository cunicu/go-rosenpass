// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"encoding/base64"
	"fmt"
	"os"

	rp "github.com/stv0g/go-rosenpass"
)

func readKeyOutFile(fn string) (rp.Key, error) {
	buf, err := os.ReadFile(fn)
	if err != nil {
		return rp.Key{}, nil
	}

	var k rp.Key
	if n, err := base64.StdEncoding.Decode(k[:], buf); err != nil {
		return rp.Key{}, fmt.Errorf("failed to decode key: %w", err)
	} else if n != 32 {
		return rp.Key{}, fmt.Errorf("partial read: %d", n)
	}

	return k, nil
}
