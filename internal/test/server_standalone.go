// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	rp "github.com/stv0g/go-rosenpass"
	"github.com/stv0g/go-rosenpass/config"
	"golang.org/x/exp/slog"
)

type StandaloneServer struct {
	cmd *exec.Cmd

	handlers []rp.Handler
	logger   *slog.Logger
}

func NewStandaloneServer(cfg rp.Config, executable, dir string) (*StandaloneServer, error) {
	s := &StandaloneServer{
		cmd: exec.Command(executable),

		handlers: cfg.Handlers,
		logger:   cfg.Logger,
	}

	if s.logger == nil {
		s.logger = slog.Default()
	}

	if len(s.handlers) > 0 {
		rd, wr := io.Pipe()

		go s.handleStdout(rd)

		s.cmd.Stdout = io.MultiWriter(os.Stdout, wr)
	} else {
		s.cmd.Stdout = os.Stdout
	}
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

func (s *StandaloneServer) handleStdout(rd io.Reader) {
	scanner := bufio.NewScanner(rd)
	for scanner.Scan() {
		line := scanner.Text()

		ko, err := rp.ParseKeyOutput(line)
		if err != nil {
			s.logger.Error("Failed to parse stdout line", slog.String("line", line), slog.Any("error", err))
			continue
		}

		switch ko.Why {
		case rp.KeyOutputReasonExchanged:
			key, err := readKeyOutFile(ko.KeyFile)
			if err != nil {
				s.logger.Error("Failed to read key file", slog.String("file", ko.KeyFile), slog.Any("error", err))
				continue
			}

			for _, h := range s.handlers {
				if h, ok := h.(rp.HandshakeCompletedHandler); ok {
					h.HandshakeCompleted(ko.Peer, key)
				}
			}

		case rp.KeyOutputReasonStale:
			for _, h := range s.handlers {
				if h, ok := h.(rp.HandshakeExpiredHandler); ok {
					h.HandshakeExpired(ko.Peer)
				}
			}
		}
	}
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
