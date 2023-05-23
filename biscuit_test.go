// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBiscuitNo(t *testing.T) {
	require := require.New(t)

	b := biscuitNo{}
	require.Equal(b.Load(), uint64(0))

	b.Inc(5)
	require.Equal(b.Load(), uint64(5))

	b.Inc(5)
	require.Equal(b.Load(), uint64(10))

	b.Store(100)
	require.Equal(b.Load(), uint64(100))

	c := biscuitNo{}
	c.Store(200)
	require.True(c.Larger(b))
}
