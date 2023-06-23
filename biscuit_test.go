// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBiscuitNo(t *testing.T) {
	require := require.New(t)

	b0 := biscuitNo{}
	b1 := biscuitNo{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	require.True(b1.Equal(b1))
	require.True(b1.Equal(b0))
	require.True(b1.LargerOrEqual(b0))

	b2 := biscuitNo{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	require.False(b1.Equal(b2))
	require.True(b2.Larger(b1))
	require.False(b1.Larger(b2))
	require.False(b2.Lesser(b1))
	require.True(b1.Lesser(b2))

	b1.Inc()
	require.True(b1.Equal(b2))

	b3 := biscuitNo{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	require.True(b3.Larger(b0))

	b4 := biscuitNo{0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	require.True(b4.Lesser(b3))
	require.True(b3.Larger(b4))

	b4.Inc()
	require.True(b3.Equal(b4))

	b4.Inc()
	require.True(b4.Equal(b0))
}
