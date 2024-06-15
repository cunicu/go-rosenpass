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
			sidi:  sid(rand(sidSize)),
			epki:  epk(rand(epkSize)),
			sctr:  sct(rand(sctSize)),
			pidiC: [pidSize + authSize]byte(rand(pidSize + authSize)),
			auth:  authTag(rand(authSize)),
		}

		buf := m1.MarshalBinary()
		require.Len(buf, initHelloMsgSize)

		sz, err := m2.UnmarshalBinary(buf)
		require.NoError(err)
		require.Equal(initHelloMsgSize, sz)

		require.Equal(m1, m2)
	})

	t.Run("RespHello", func(t *testing.T) {
		require := require.New(t)

		var err error
		var m2 respHello
		m1 := respHello{
			sidr:    sid(rand(sidSize)),
			sidi:    sid(rand(sidSize)),
			ecti:    ect(rand(ectSize)),
			scti:    sct(rand(sctSize)),
			auth:    authTag(rand(authSize)),
			biscuit: sealedBiscuit(rand(sealedBiscuitSize)),
		}

		buf := m1.MarshalBinary()
		require.Len(buf, respHelloMsgSize)

		sz, err := m2.UnmarshalBinary(buf)
		require.NoError(err)
		require.Equal(respHelloMsgSize, sz)

		require.Equal(m1, m2)
	})

	t.Run("InitConf", func(t *testing.T) {
		require := require.New(t)

		var err error
		var m2 initConf
		m1 := initConf{
			sidi:    sid(rand(sidSize)),
			sidr:    sid(rand(sidSize)),
			biscuit: sealedBiscuit(rand(sealedBiscuitSize)),
			auth:    authTag(rand(authSize)),
		}

		m1.sidi, err = generateSessionID()
		require.NoError(err)

		buf := m1.MarshalBinary()
		require.Len(buf, initConfMsgSize)

		sz, err := m2.UnmarshalBinary(buf)
		require.NoError(err)
		require.Equal(initConfMsgSize, sz)

		require.Equal(m1, m2)
	})

	t.Run("EmptyData", func(t *testing.T) {
		require := require.New(t)

		var err error
		var m2 emptyData
		m1 := emptyData{
			sid:  sid(rand(sidSize)),
			ctr:  txNonce(rand(txNonceSize)),
			auth: authTag(rand(authSize)),
		}

		m1.sid, err = generateSessionID()
		require.NoError(err)

		buf := m1.MarshalBinary()
		require.Len(buf, emptyDataMsgSize)

		sz, err := m2.UnmarshalBinary(buf)
		require.NoError(err)
		require.Equal(emptyDataMsgSize, sz)

		require.Equal(m1, m2)
	})
}

func FuzzEnvelope(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) {
		var e envelope
		e.UnmarshalBinary(b) //nolint:errcheck
	})
}
