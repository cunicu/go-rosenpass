// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

var (
	lblProtocol                   = []byte("Rosenpass v1 mceliece460896 Kyber512 ChaChaPoly1305 BLAKE2s")
	lblMAC                        = []byte("mac")
	lblCookie                     = []byte("cookie")
	lblPeerID                     = []byte("peer id")
	lblBiscuitAdditionalData      = []byte("biscuit additional data")
	lblChainingKeyExtract         = []byte("chaining key extract")
	lblChainingKeyInit            = []byte("chaining key init")
	lblMix                        = []byte("mix")
	lblResponderSessionEncryption = []byte("responder handshake encryption")
	lblInitiatorSessionEncryption = []byte("initiator handshake encryption")
	lblHandshakeEncryption        = []byte("handshake encryption")
	lblUser                       = []byte("user")
	lblRosenpass                  = []byte("rosenpass")
	lblWireGuardPSK               = []byte("wireguard psk")
)
