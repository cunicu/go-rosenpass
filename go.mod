// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

module cunicu.li/go-rosenpass

go 1.23.0

toolchain go1.24.5

require (
	github.com/cilium/ebpf v0.19.0
	github.com/cloudflare/circl v1.3.3
	github.com/gopacket/gopacket v1.3.1
	github.com/mdlayher/socket v0.5.1
	github.com/pelletier/go-toml/v2 v2.2.4
	github.com/spf13/cobra v1.9.1
	golang.org/x/crypto v0.40.0
	golang.org/x/sys v0.34.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
)

require github.com/stretchr/testify v1.10.0 // testing

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.6 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173 // indirect
	gopkg.in/ini.v1 v1.67.0
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// For Classic McEliece support
// Based on older version of https://github.com/cloudflare/circl/pull/378
// implementing the round 3 version of Classic McEliece without plaintext confirmation
replace github.com/cloudflare/circl => github.com/cunicu/circl v0.0.0-20230801113412-fec58fc7b5f6
