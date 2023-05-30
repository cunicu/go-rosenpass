// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	rp "github.com/stv0g/go-rosenpass"
	"golang.org/x/exp/slog"
)

func keyoutWatcher(fn string, h func(rp.Key)) (*fsnotify.Watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	dir := filepath.Dir(fn)
	if err := w.Add(dir); err != nil {
		return nil, fmt.Errorf("failed to watch file %s: %w", fn, err)
	}

	go watchKeyOutFile(fn, w.Events, h)

	return w, nil
}

func readKeyOutFile(fn string) (rp.Key, error) {
	buf, err := os.ReadFile(fn)
	if err != nil {
		return rp.Key{}, nil
	}

	var k rp.Key
	if n, err := base64.StdEncoding.Decode(k[:], buf); err != nil {
		return rp.Key{}, fmt.Errorf("failed to decode key: %w", err)
	} else if n != 32 {
		return rp.Key{}, fmt.Errorf("partial read: %d", n)
	}

	return k, nil
}

func watchKeyOutFile(fn string, events chan fsnotify.Event, h func(rp.Key)) {
	for e := range events {
		if e.Name != fn || e.Op != fsnotify.Write {
			continue
		}

		if key, err := readKeyOutFile(fn); err != nil {
			slog.Error("Failed to read keyout file", slog.Any("error", err))
		} else {
			h(key)
		}
	}
}
