# SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
# SPDX-License-Identifier: Apache-2.0

all: go-rosenpass

go-rosenpass:
	go build -o $@ ./cmd

lint:
	golangci-lint run ./...

.PHONY: lint all go-rosenpass
