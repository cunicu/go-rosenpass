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

	args, cfg, err := config.FromArgs([]string{
		"public-key", "pk",
		"secret-key", "sk",
		"listen", "lst",
		"verbose",
		"peer", "public-key", "a_pk", "preshared-key", "a_psk", "endpoint", "a_ep", "outfile", "a_of", "wireguard", "a_wg", "jm0556G9mvQB8ZG7FdNR4SaLRc83VVoyTG2D9NWecS4=",
		"peer", "public-key", "b_pk", "preshared-key", "b_psk", "endpoint", "b_ep", "outfile", "b_of", "wireguard", "b_wg", "0oXsRjHLMaWXfDDaWQEHpyCvXA6XsfMv1A8aV2k0ZSo=",
	})
	require.NoError(err)
	require.Empty(args)

	require.Equal("pk", cfg.PublicKey)
	require.Equal("sk", cfg.SecretKey)
	require.Equal([]string{"lst"}, cfg.ListenAddrs)
	require.Equal("Verbose", cfg.Verbosity)

	require.Len(cfg.Peers, 2)

	for peer, p := range map[string]config.PeerSection{
		"a": cfg.Peers[0],
		"b": cfg.Peers[1],
	} {
		require.Equal(peer+"_pk", p.PublicKey)

		require.NotNil(p.PresharedKey)
		require.Equal(peer+"_psk", *p.PresharedKey)

		require.NotNil(p.Endpoint)
		require.Equal(peer+"_ep", *p.Endpoint)

		require.NotNil(p.KeyOut)
		require.Equal(peer+"_of", *p.KeyOut)

		require.NotNil(p.WireGuard)
		require.Equal(peer+"_wg", p.WireGuard.Interface)

		if peer == "a" {
			require.Equal("jm0556G9mvQB8ZG7FdNR4SaLRc83VVoyTG2D9NWecS4=", p.WireGuard.PublicKey.String())
		} else {
			require.Equal("0oXsRjHLMaWXfDDaWQEHpyCvXA6XsfMv1A8aV2k0ZSo=", p.WireGuard.PublicKey.String())
		}
	}
}
