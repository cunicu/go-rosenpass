// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

var (
	lblProtocol                   = []byte("rosenpass 1 rosenpass.eu aead=chachapoly1305 hash=blake2s ekem=kyber512 skem=mceliece460896 xaead=xchachapoly1305")
	lblMac                        = []byte("mac")
	lblCookie                     = []byte("cookie")
	lblPeerID                     = []byte("peer id")
	lblBiscuitAdditionalData      = []byte("biscuit additional data")
	lblChainingKeyExtract         = []byte("chaining key extract")
	lblChainingKeyInit            = []byte("chainging key init")
	lblMix                        = []byte("mix")
	lblResponderSessionEncryption = []byte("responder session encryption")
	lblInitiatorSessionEncryption = []byte("initiator session encryption")
	lblHandshakeEncryption        = []byte("handshake encryption")
	lblUser                       = []byte("user")
	lblRosenpass                  = []byte("rosenpass")
	lblWireGuardPSK               = []byte("wireguard psk")
)
