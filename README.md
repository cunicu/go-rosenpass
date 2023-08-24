# go-rosenpass

<!-- [![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/cunicu/go-rosenpass/test.yaml?style=flat-square)](https://github.com/cunicu/go-rosenpass/actions) -->
[![Codecov branch](https://img.shields.io/codecov/c/github/cunicu/go-rosenpass/main?style=flat-square&token=xUGG2iEsuQ)](https://app.codecov.io/gh/cunicu/go-rosenpass/tree/main)
[![goreportcard](https://goreportcard.com/badge/github.com/cunicu/go-rosenpass?style=flat-square)](https://goreportcard.com/report/github.com/cunicu/go-rosenpass)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](https://github.com/cunicu/go-rosenpass/blob/main/LICENSES/Apache-2.0.txt)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/cunicu/go-rosenpass?style=flat-square)
[![Go Reference](https://pkg.go.dev/badge/github.com/cunicu/go-rosenpass.svg)](https://pkg.go.dev/github.com/cunicu/go-rosenpass)

🚧 go-rosenpass has not been audited. Please use with care!

go-rosenpass is a port of [Rosenpass](https://github.com/rosenpass/rosenpass) to [Go](https://go.dev/).

The implementation aims to be compatible with the reference implementation in Rust for the:
- on-wire protocol
- handshake parameters
- command-line interface

## Installation

### Pre-build binaries

_go-rosenpass_ distributes builds via [GitHub Releases](https://github.com/cunicu/go-rosenpass/releases).
You can download a pre-built binary from there.

## References

- <https://github.com/rosenpass/rosenpass>
- <https://rosenpass.eu/>
- <https://media.ccc.de/v/eh20-4-rosenpass-ein-vpn-zum-schutz-vor-quantencomputern>

## Authors

- Steffen Vogel ([@stv0g](https://github.com/stv0g))

## License

go-rosenpass is licensed under the [Apache 2.0](./LICENSE) license.

- SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
- SPDX-License-Identifier: Apache-2.0