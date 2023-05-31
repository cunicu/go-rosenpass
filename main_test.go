// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"os"
	"testing"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slog"
)

func TestMain(m *testing.M) {
	textHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(textHandler)

	slog.SetDefault(logger)

	m.Run()
}

// TestLibOQS verifies that liboqs supports the required
// KEM algorithms for rosenpass
func TestLibOQS(t *testing.T) {
	require := require.New(t)

	require.True(oqs.IsKEMEnabled(kemAlgEphemeral))
	require.True(oqs.IsKEMEnabled(kemAlgStatic))
}
