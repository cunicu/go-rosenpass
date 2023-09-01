// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	rp "cunicu.li/go-rosenpass"
	"gopkg.in/ini.v1"
)

func FromWireGuardInterface(intfName string) (cfgFile File, err error) {
	wgDir := "/etc/wireguard"

	wgCfgFile := filepath.Join(wgDir, intfName+".conf")
	wgCfg, err := ini.Load(wgCfgFile)
	if err != nil {
		return cfgFile, fmt.Errorf("failed to load config file")
	}

	intfDir := filepath.Join(wgDir, intfName)
	if fi, err := os.Stat(intfDir); err != nil || !fi.IsDir() {
		return cfgFile, fmt.Errorf("missing configuration for interface: %s", intfName)
	}

	intfSection := wgCfg.Section("Interface")

	listenPortKey := intfSection.Key("ListenPort")
	if listenPortKey == nil {
		return cfgFile, errors.New("missing listen port")
	}

	listenPort, err := listenPortKey.Int()
	if err != nil {
		return cfgFile, fmt.Errorf("failed to get listen port: %w", err)
	}

	privateKey := intfSection.Key("PrivateKey")
	if privateKey == nil {
		return cfgFile, errors.New("missing private key")
	}

	cfgFile = File{
		PublicKey: filepath.Join(intfDir, "pqpk"),
		SecretKey: filepath.Join(intfDir, "pqsk"),
		ListenAddrs: []string{
			fmt.Sprintf("0.0.0.0:%d", listenPort), //nolint:forbidigo
			fmt.Sprintf("[::]:%d", listenPort),    //nolint:forbidigo
		},
		ListenSinglePort: true,
	}

	peerSections, err := wgCfg.SectionsByName("Peer")
	if err != nil {
		return cfgFile, fmt.Errorf("failed to find peer configs: %w", err)
	}

	for _, peerSection := range peerSections {
		pkKey := peerSection.Key("PublicKey")
		if pkKey == nil {
			return cfgFile, fmt.Errorf("missing public key")
		}

		pkBytes, err := base64.StdEncoding.DecodeString(pkKey.String())
		if err != nil || len(pkBytes) != 32 {
			return cfgFile, fmt.Errorf("failed to parse public key: %w", err)
		}

		pk := strings.ReplaceAll(pkKey.String(), string(filepath.Separator), "")
		pkFile := fmt.Sprintf("%s/%s.pqpk", intfDir, pk)   //nolint:forbidigo
		pskFile := fmt.Sprintf("%s/%s.pqpsk", intfDir, pk) //nolint:forbidigo

		if fi, err := os.Stat(pkFile); err != nil || fi.IsDir() {
			continue
		}

		cfgPeer := PeerSection{
			PublicKey: pkFile,
			WireGuard: &WireGuardSection{
				Interface: intfName,
				PublicKey: rp.Key(pkBytes),
			},
		}

		if epKey := peerSection.Key("Endpoint"); epKey != nil {
			ep := epKey.String()
			cfgPeer.Endpoint = &ep
		}

		if fi, err := os.Stat(pskFile); err == nil && !fi.IsDir() {
			cfgPeer.PresharedKey = &pskFile
		}

		cfgFile.Peers = append(cfgFile.Peers, cfgPeer)
	}

	return cfgFile, nil
}
