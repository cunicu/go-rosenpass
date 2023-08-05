// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build wgcmd || !cgo || !(freebsd || openbsd)

package config

import (
	"bytes"
	"os"
	"os/exec"
	"strings"

	rp "github.com/stv0g/go-rosenpass"
	"golang.org/x/exp/slog"
)

type wireGuardHandler struct {
	peers map[rp.PeerID]WireGuardSection
}

func newWireGuardHandler() (hdlr *wireGuardHandler, err error) {
	return &wireGuardHandler{
		peers: map[rp.PeerID]WireGuardSection{},
	}, nil
}

func (h *wireGuardHandler) outputKey(_ rp.KeyOutputReason, pid rp.PeerID, psk rp.Key) {
	wg, ok := h.peers[pid]
	if !ok {
		return
	}

	logger := slog.With(
		slog.Any("interface", wg.Interface),
		slog.Any("peer", wg.PublicKey),
	)

	pskB64, err := psk.MarshalText()
	if err != nil {
		logger.Error("Failed marshal preshared-key", slog.Any("error", err))
		return
	}

	rdSide, wrSide, err := os.Pipe()
	if err != nil {
		logger.Error("Failed to create pipe", slog.Any("error", err))
		return
	}

	out := &bytes.Buffer{}

	c := exec.Command("wg", "set", wg.Interface, "peer", wg.PublicKey.String(), "preshared-key", "/dev/fd/3") //nolint:gosec
	c.ExtraFiles = append(c.ExtraFiles, rdSide)
	c.Stdout = out
	c.Stderr = out

	if err := c.Start(); err != nil {
		logger.Error("Failed to run wg", slog.Any("error", err))
		return
	}

	if _, err := wrSide.Write(pskB64); err != nil {
		logger.Error("Failed to write to pipe", slog.Any("error", err))
	}

	if err := wrSide.Close(); err != nil {
		logger.Error("Failed to close pipe", slog.Any("error", err))
	}

	if err := c.Wait(); err != nil {
		outStr := strings.TrimSpace(out.String())
		logger.Error("Failed to configure WireGuard interface",
			slog.Any("error", err),
			slog.String("output", outStr))
	}
}
