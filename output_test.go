// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass_test

import (
	"testing"

	rp "cunicu.li/go-rosenpass"

	"github.com/stretchr/testify/require"
)

func TestOutput(t *testing.T) {
	require := require.New(t)

	spk, _, err := rp.GenerateKeyPair()
	require.NoError(err)

	koExpected := rp.KeyOutput{
		Peer:    rp.PeerIDFromPublicKey(spk),
		KeyFile: "some_keyfile",
		Why:     rp.KeyOutputReasonExchanged,
	}
	koStr := koExpected.String()

	koActual, err := rp.ParseKeyOutput(koStr)
	require.NoError(err)

	require.Equal(koExpected, koActual)
}
