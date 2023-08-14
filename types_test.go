// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass_test

import (
	"testing"

	rp "cunicu.li/go-rosenpass"

	"github.com/stretchr/testify/require"
)

func TestKey(t *testing.T) {
	require := require.New(t)

	var k1, k2 rp.Key

	k1, err := rp.GeneratePresharedKey()
	require.NoError(err)

	text, err := k1.MarshalText()
	require.NoError(err)

	err = k2.UnmarshalText(text)
	require.NoError(err)

	require.Equal(k2.String(), string(text))
}
