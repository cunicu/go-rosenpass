// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	rp "cunicu.li/go-rosenpass"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func FromWireGuardInterface(intfName string) (cfgFile File, err error) {
	client, err := wgctrl.New()
	if err != nil {
		return cfgFile, fmt.Errorf("failed to create wg cleint: %w", err)
	}

	dir := filepath.Join("/etc/wireguard", intfName)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return cfgFile, fmt.Errorf("missing configuration for interface: %s", intfName)
	}

	dev, err := client.Device(intfName)
	if err != nil {
		return cfgFile, fmt.Errorf("failed to get interface: %w", err)
	}

	if dev.ListenPort == 0 {
		return cfgFile, errors.New("missing listen port")
	}

	emptyKey := wgtypes.Key{}
	if dev.PublicKey == emptyKey {
		return cfgFile, errors.New("missing public key")
	}

	cfgFile = File{
		PublicKey: filepath.Join(dir, "pqpk"),
		SecretKey: filepath.Join(dir, "pqsk"),
		ListenAddrs: []string{
			fmt.Sprintf("0.0.0.0:%d", dev.ListenPort), //nolint:forbidigo
			fmt.Sprintf("[::]:%d", dev.ListenPort),    //nolint:forbidigo
		},
		ListenSinglePort: true,
	}

	for _, peer := range dev.Peers {
		pk := strings.ReplaceAll(peer.PublicKey.String(), string(filepath.Separator), "")
		pkFile := fmt.Sprintf("%s/%s.pqpk", dir, pk)   //nolint:forbidigo
		pskFile := fmt.Sprintf("%s/%s.pqpsk", dir, pk) //nolint:forbidigo

		if fi, err := os.Stat(pkFile); err != nil || fi.IsDir() {
			continue
		}

		cfgPeer := PeerSection{
			PublicKey: pkFile,
			WireGuard: &WireGuardSection{
				Interface: intfName,
				PublicKey: rp.Key(peer.PublicKey),
			},
		}

		if peer.Endpoint != nil {
			ep := peer.Endpoint.String()
			cfgPeer.Endpoint = &ep
		}

		if fi, err := os.Stat(pskFile); err == nil && !fi.IsDir() {
			cfgPeer.PresharedKey = &pskFile
		}

		cfgFile.Peers = append(cfgFile.Peers, cfgPeer)
	}

	return cfgFile, nil
}
