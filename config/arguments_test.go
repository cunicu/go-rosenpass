// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stv0g/go-rosenpass/config"
)

func TestArguments(t *testing.T) {
	require := require.New(t)

	args, cfg, err := config.ConfigFromArgs([]string{
		"public-key", "pk",
		"private-key", "sk",
		"listen", "lst",
		"verbose",
		"peer", "public-key", "a_pk", "preshared-key", "a_psk", "endpoint", "a_ep", "outfile", "a_of", "wireguard", "a_wg", "a_wg_pk",
		"peer", "public-key", "b_pk", "preshared-key", "b_psk", "endpoint", "b_ep", "outfile", "b_of", "wireguard", "b_wg", "b_wg_pk",
	})
	require.NoError(err)
	require.Empty(args)

	require.Equal("pk", cfg.PublicKey)
	require.Equal("sk", cfg.SecretKey)
	require.Equal([]string{"lst"}, cfg.Listen)
	require.Equal("Verbose", cfg.Verbosity)

	require.Len(cfg.Peers, 2)

	for pfx, p := range map[string]config.PeerSection{
		"a_": cfg.Peers[0],
		"b_": cfg.Peers[1],
	} {
		require.Equal(pfx+"pk", p.PublicKey)

		require.NotNil(p.PresharedKey)
		require.Equal(pfx+"psk", *p.PresharedKey)

		require.NotNil(p.Endpoint)
		require.Equal(pfx+"ep", *p.Endpoint)

		require.NotNil(p.KeyOut)
		require.Equal(pfx+"of", *p.KeyOut)

		require.NotNil(p.WireGuard)
		require.Equal(pfx+"wg", p.WireGuard.Interface)
		require.Equal(pfx+"wg_pk", p.WireGuard.PublicKey)
	}
}
