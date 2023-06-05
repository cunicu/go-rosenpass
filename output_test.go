// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	rp "github.com/stv0g/go-rosenpass"
)

func TestOutput(t *testing.T) {
	require := require.New(t)

	buffer := bytes.NewBuffer(nil)

	_, spk, err := rp.GenerateKeyPair()
	require.NoError(err)

	o := rp.KeyOutput{
		Peer:    rp.PeerIDFromPublicKey(spk),
		KeyFile: "some_keyfile",
		Why:     rp.KeyOutputReasonExchanged,
	}

	_, err = o.Dump(buffer)
	require.NoError(err)

	p, err := rp.ScanKeyOutput(buffer)
	require.NoError(err)

	require.Equal(o, p)
}
