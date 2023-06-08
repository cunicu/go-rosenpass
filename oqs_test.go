// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package rosenpass

import (
	"testing"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"github.com/stretchr/testify/require"
)

// TestLibOQS verifies that liboqs supports the required
// KEM algorithms for rosenpass
func TestLibOQS(t *testing.T) {
	require := require.New(t)

	require.True(oqs.IsKEMEnabled(kemEphemeral))
	require.True(oqs.IsKEMEnabled(kemStatic))
}
