module github.com/stv0g/go-rosenpass

go 1.20

require (
	github.com/cloudflare/circl v0.0.0-00010101000000-000000000000
	github.com/open-quantum-safe/liboqs-go v0.0.0-20230705192921-cf9c63b76ce6
	github.com/pelletier/go-toml/v2 v2.0.9
	github.com/spf13/cobra v1.7.0
	golang.org/x/crypto v0.12.0
	golang.org/x/exp v0.0.0-20230801115018-d63ba01acd4b
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6
)

require github.com/stretchr/testify v1.8.4 // testing

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.11.0 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20230325221338-052af4a8072b // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// For Classic McEliece support
// Based on older version of https://github.com/cloudflare/circl/pull/378
// implementing the round 3 version of Classic McEliece without plaintext confirmation
replace github.com/cloudflare/circl => github.com/stv0g/circl 099d31380290
