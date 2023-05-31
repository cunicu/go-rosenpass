// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	rp "github.com/stv0g/go-rosenpass"
	"github.com/stv0g/go-rosenpass/config"
)

type StandaloneServer struct {
	cmd *exec.Cmd
}

func NewStandaloneServer(cfg rp.Config, executable, dir string) (*StandaloneServer, error) {
	s := &StandaloneServer{
		cmd: exec.Command(executable),
	}

	s.cmd.Stdout = os.Stdout
	s.cmd.Stderr = os.Stderr

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	cfgFile := config.File{}
	if err := cfgFile.FromConfig(cfg, dir); err != nil {
		return nil, err
	}

	cfgFileName := filepath.Join(dir, "config.toml")

	if err := cfgFile.DumpFile(cfgFileName); err != nil {
		return nil, err
	}

	s.cmd.Args = append(s.cmd.Args, "exchange-config", cfgFileName)

	return s, nil
}

func (s *StandaloneServer) Run() error {
	log.Printf("Starting rosenpass %s", strings.Join(s.cmd.Args, " "))

	return s.cmd.Start()
}

func (s *StandaloneServer) Close() error {
	if err := s.cmd.Process.Signal(os.Interrupt); err != nil {
		return fmt.Errorf("failed to interrupt process: %w", err)
	}

	if err := s.cmd.Wait(); err != nil {
		var exErr *exec.ExitError
		if !errors.As(err, &exErr) {
			return fmt.Errorf("failed to wait for process termination: %w", err)
		}
	}

	return nil
}
