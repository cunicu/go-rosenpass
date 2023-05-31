// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"errors"
	"flag"
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
	log.Printf("Starting %s", strings.Join(s.cmd.Args, " "))

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

type StandaloneGoServer struct {
	*StandaloneServer

	coverDir string
}

func NewStandaloneGoServer(cfg rp.Config, dir string) (*StandaloneGoServer, error) {
	var coverPkg, coverDir string
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != f.DefValue {
		coverPkg = "./..."
	}

	executable, err := EnsureBuild(coverPkg)
	if err != nil {
		return nil, err
	}

	s, err := NewStandaloneServer(cfg, executable, dir)
	if err != nil {
		return nil, err
	}

	if coverPkg != "" {
		coverDir = dir
		s.cmd.Env = append(s.cmd.Env, fmt.Sprintf("GOCOVERDIR=%s", coverDir))
	}

	return &StandaloneGoServer{
		StandaloneServer: s,
		coverDir:         coverDir,
	}, nil
}

func (s *StandaloneGoServer) Close() error {
	pid := s.cmd.Process.Pid

	if err := s.StandaloneServer.Close(); err != nil {
		return err
	}

	if s.coverDir != "" {
		output := fmt.Sprintf("coverage-%d.out", pid)
		if err := s.convertCoverage(output); err != nil {
			return fmt.Errorf("failed to convert coverage data: %w", err)
		}
	}

	return nil
}

func (s *StandaloneGoServer) convertCoverage(outputFile string) error {
	c := exec.Command("go", "tool", "covdata", "textfmt", "-i", s.coverDir, "-o", outputFile)
	c.Stderr = os.Stderr
	c.Stdout = os.Stdout

	return c.Run()
}
