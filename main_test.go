// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass_test

import (
	"log/slog"
	"os"
	"testing"
	"time"

	rp "github.com/stv0g/go-rosenpass"
)

func TestMain(m *testing.M) {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, opts)))

	// Adjust protocol parameters for tests
	rp.RekeyAfterTimeResponder = 1 * time.Second
	rp.RekeyAfterTimeInitiator = rp.RekeyAfterTimeResponder + time.Second
	rp.RejectAfterTime = 2 * time.Second
	rp.BiscuitEpoch = 3 * time.Second

	m.Run()
}
