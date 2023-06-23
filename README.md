# go-rosenpass

<!-- [![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/stv0g/go-rosenpass/test.yaml?style=flat-square)](https://github.com/stv0g/go-rosenpass/actions) -->
[![Codecov branch](https://img.shields.io/codecov/c/github/stv0g/go-rosenpass/master?style=flat-square&token=xUGG2iEsuQ)](https://app.codecov.io/gh/stv0g/go-rosenpass/tree/master)
[![goreportcard](https://goreportcard.com/badge/github.com/stv0g/go-rosenpass?style=flat-square)](https://goreportcard.com/report/github.com/stv0g/go-rosenpass)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](https://github.com/stv0g/go-rosenpass/blob/master/LICENSES/Apache-2.0.txt)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/stv0g/go-rosenpass?style=flat-square)
[![Go Reference](https://pkg.go.dev/badge/github.com/stv0g/go-rosenpass.svg)](https://pkg.go.dev/github.com/stv0g/go-rosenpass)

🚧 go-rosenpass has not been audited. Please use with care!

go-rosenpass is a port of [Rosenpass](https://github.com/rosenpass/rosenpass) to [Go](https://go.dev/).

The implementation aims to be compatible with the reference implementation in Rust for the:
- on-wire protocol
- handshake parameters
- command-line interface

## Installation

### Pre-build binaries

_go-rosenpass_ distributes builds via [GitHub Releases](https://github.com/stv0g/go-rosenpass/releases).
You can download a pre-built binary from there.

### Building from source

_go-rosenpass_ requires [liboqs](https://github.com/open-quantum-safe/liboqs) for Post-Quantum crypto primitives.
Please have a look the [liboqs-go](https://github.com/open-quantum-safe/liboqs-go) bindings for details build instructions.

#### Linking statically against liboqs & libcrypto

In addition to the instruction provided by liboqs-go, its also possible to link _go-rosenpass_ statically against liboqs using the following commands:

```bash
git clone https://github.com/stv0g/go-rosenpass
cd go-rosenpass
PKG_CONFIG_PATH=.config-static go build -o go-rosenpass ./cmd/
```

The resulting `go-rosenpass` binary can be redistributed without requiring `liboqs.so` or `libcrypto.so` as external dependencies.

## References

- <https://github.com/rosenpass/rosenpass>
- <https://rosenpass.eu/>
- <https://media.ccc.de/v/eh20-4-rosenpass-ein-vpn-zum-schutz-vor-quantencomputern>

## Authors

- Steffen Vogel ([@stv0g](https://github.com/stv0g))

## License

go-rosenpass is licensed under the Apache 2.0 license.

- SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
- SPDX-License-Identifier: Apache-2.0