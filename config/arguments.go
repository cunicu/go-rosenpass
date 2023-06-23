// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"

	rp "github.com/stv0g/go-rosenpass"
	"golang.org/x/exp/slog"
)

var (
	ErrMissingPublicKey = errors.New("missing public key")
	ErrMissingSecretKey = errors.New("missing private key")
)

func popUntil(s []string, n string) (ps []string, _ []string) {
	var p string
	for len(s) > 0 && s[0] != n {
		p, s = pop(s)
		ps = append(ps, p)
	}

	return ps, s
}

func pop(s []string) (string, []string) {
	return s[0], s[1:]
}

// Parse exchange config from CLI args
// Format: private-key <file-path> public-key <file-path> [ OPTIONS ] PEERS
func ConfigFromArgs(args []string) (_ []string, cfg File, err error) {
	var arg string

	for len(args) > 0 && args[0] != "peer" {
		arg, args = pop(args)
		switch arg {
		case "private-key":
			slog.Warn("the private-key argument is deprecated, please use secret-key instead")
			fallthrough

		case "secret-key":
			if len(args) < 1 {
				return nil, cfg, fmt.Errorf("truncated arguments: missing private-key <file-path>")
			}

			cfg.SecretKey, args = pop(args)

		case "public-key":
			if len(args) < 1 {
				return nil, cfg, fmt.Errorf("truncated arguments: missing public-key <file-path>")
			}

			cfg.PublicKey, args = pop(args)

		case "listen":
			if len(args) < 1 {
				return nil, cfg, fmt.Errorf("truncated arguments: missing <ip>[:<port>]")
			}

			var lst string
			lst, args = pop(args)
			cfg.ListenAddrs = append(cfg.ListenAddrs, lst)

		case "verbose":
			cfg.Verbosity = "Verbose"

		default:
			return nil, cfg, fmt.Errorf("invalid argument: %s", arg)
		}
	}

	// Checks
	if cfg.PublicKey == "" {
		return nil, cfg, ErrMissingPublicKey
	} else if cfg.SecretKey == "" {
		return nil, cfg, ErrMissingSecretKey
	}

	for len(args) > 0 {
		arg, args = pop(args)
		switch arg {
		case "peer":
			var pc PeerSection
			if args, pc, err = PeerConfigFromArgs(args); err != nil {
				return nil, cfg, err
			}

			cfg.Peers = append(cfg.Peers, pc)

		default:
			return nil, cfg, fmt.Errorf("invalid argument: %s", arg)
		}
	}

	return args, cfg, nil
}

// Parse peer config from CLI arguments
// Format: peer public-key <file-path> [endpoint <ip>[:<port>]] [preshared-key <file-path>] [outfile <file-path>] [wireguard <dev> <peer> <extra_params>]
func PeerConfigFromArgs(args []string) (_ []string, cfg PeerSection, err error) {
	var arg string

	for len(args) > 0 && args[0] != "peer" {
		arg, args = pop(args)
		switch arg {
		case "public-key":
			if len(args) < 1 {
				return nil, cfg, fmt.Errorf("truncated arguments: missing public-key <file-path>")
			}

			cfg.PublicKey, args = pop(args)

		case "preshared-key":
			if len(args) < 1 {
				return nil, cfg, fmt.Errorf("truncated arguments: missing preshared-key <file-path>")
			}

			var psk string
			psk, args = pop(args)
			cfg.PresharedKey = &psk

		case "endpoint":
			if len(args) < 1 {
				return nil, cfg, fmt.Errorf("truncated arguments: missing <ip>[:<port>]")
			}

			var ep string
			ep, args = pop(args)
			cfg.Endpoint = &ep

		case "outfile":
			if len(args) < 1 {
				return nil, cfg, fmt.Errorf("truncated arguments: missing outfile <file-path>")
			}

			var of string
			of, args = pop(args)
			cfg.KeyOut = &of

		case "wireguard":
			if len(args) < 2 {
				return nil, cfg, fmt.Errorf("truncated arguments: missing <dev> <peer> <extra_params>")
			}

			var dev, peer string

			dev, args = pop(args)
			peer, args = pop(args)
			_, args = popUntil(args, "peer") // ExtraArgs are ignored for now

			var pk rp.Key
			if err := pk.UnmarshalText([]byte(peer)); err != nil {
				return nil, cfg, fmt.Errorf("invalid public peer key '%s': %w", peer, err)
			}

			cfg.WireGuard = &WireGuardSection{
				Interface: dev,
				PublicKey: pk,
			}

		default:
			return nil, cfg, fmt.Errorf("invalid argument: %s", arg)
		}
	}

	// Checks
	if cfg.PublicKey == "" {
		return nil, cfg, ErrMissingPublicKey
	}

	return args, cfg, nil
}
