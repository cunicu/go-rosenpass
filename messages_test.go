// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMessages(t *testing.T) {
	rand := func(n int) []byte {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			t.Fatalf("Failed to generate test data: %s", err)
		}
		return b
	}

	t.Run("InitHello", func(t *testing.T) {
		require := require.New(t)

		var err error
		var m2 initHello
		m1 := initHello{
			sidi:  *(*sessionID)(rand(sessionIDSize)),
			epki:  *(*ephemeralPublicKey)(rand(ephemeralPublicKeySize)),
			sctr:  *(*staticCipherText)(rand(staticCipherTextSize)),
			pidiC: *(*[48]byte)(rand(48)),
			auth:  *(*authTag)(rand(authSize)),
		}

		buf := m1.MarshalBinary()
		require.Len(buf, initHelloSize)

		sz, err := m2.UnmarshalBinary(buf)
		require.NoError(err)
		require.Equal(initHelloSize, sz)

		require.Equal(m1, m2)
	})

	t.Run("RespHello", func(t *testing.T) {
		require := require.New(t)

		var err error
		var m2 respHello
		m1 := respHello{
			sidr: *(*sessionID)(rand(sessionIDSize)),
			sidi: *(*sessionID)(rand(sessionIDSize)),
			ecti: *(*ephemeralCipherText)(rand(ephemeralCipherTextSize)),
			scti: *(*staticCipherText)(rand(staticCipherTextSize)),
			auth: *(*authTag)(rand(authSize)),
			biscuit: sealedBiscuit{
				data:  *(*[biscuitSize]byte)(rand(biscuitSize)),
				nonce: *(*nonce)(rand(nonceSize)),
				auth:  *(*authTag)(rand(authSize)),
			},
		}

		buf := m1.MarshalBinary()
		require.Len(buf, respHelloSize)

		sz, err := m2.UnmarshalBinary(buf)
		require.NoError(err)
		require.Equal(respHelloSize, sz)

		require.Equal(m1, m2)
	})

	t.Run("InitConf", func(t *testing.T) {
		require := require.New(t)

		var err error
		var m2 initConf
		m1 := initConf{
			sidi: *(*sessionID)(rand(sessionIDSize)),
			sidr: *(*sessionID)(rand(sessionIDSize)),
			biscuit: sealedBiscuit{
				data:  *(*[biscuitSize]byte)(rand(biscuitSize)),
				nonce: *(*nonce)(rand(nonceSize)),
				auth:  *(*authTag)(rand(authSize)),
			},
			auth: *(*authTag)(rand(authSize)),
		}

		m1.sidi, err = generateSessionID()
		require.NoError(err)

		buf := m1.MarshalBinary()
		require.Len(buf, initConfSize)

		sz, err := m2.UnmarshalBinary(buf)
		require.NoError(err)
		require.Equal(initConfSize, sz)

		require.Equal(m1, m2)
	})

	t.Run("EmptyData", func(t *testing.T) {
		require := require.New(t)

		var err error
		var m2 emptyData
		m1 := emptyData{
			sid:  *(*sessionID)(rand(sessionIDSize)),
			ctr:  *(*[8]byte)(rand(8)),
			auth: *(*authTag)(rand(authSize)),
		}

		m1.sid, err = generateSessionID()
		require.NoError(err)

		buf := m1.MarshalBinary()
		require.Len(buf, emptyDataSize)

		sz, err := m2.UnmarshalBinary(buf)
		require.NoError(err)
		require.Equal(emptyDataSize, sz)

		require.Equal(m1, m2)
	})
}

func FuzzEnvelope(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		var e envelope
		e.UnmarshalBinary(b) //nolint:errcheck
	})
}
