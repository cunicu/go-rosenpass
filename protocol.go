// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

var (
	lblProtocol                     = []byte("Rosenpass v1 mceliece460896 Kyber512 ChaChaPoly1305 BLAKE2s")
	lblMAC                          = []byte("mac")
	lblCookie                       = []byte("cookie") //nolint:unused
	lblPeerID                       = []byte("peer id")
	lblBiscuitAdditionalData        = []byte("biscuit additional data")
	lblChainingKeyExtract           = []byte("chaining key extract")
	lblChainingKeyInit              = []byte("chaining key init")
	lblMix                          = []byte("mix")
	lblResponderHandshakeEncryption = []byte("responder handshake encryption")
	lblInitiatorHandshakeEncryption = []byte("initiator handshake encryption")
	lblHandshakeEncryption          = []byte("handshake encryption")
	lblUser                         = []byte("user")
	lblRosenpassEU                  = []byte("rosenpass.eu")
	lblWireGuardPSK                 = []byte("wireguard psk")
)

// Precompute heyed hash functions (kh*)
var (
	khProto                 = key{}.hash(lblProtocol)
	khCKE                   = khProto.hash(lblChainingKeyExtract)
	khCKI                   = khProto.hash(lblChainingKeyInit)
	khMAC                   = khProto.hash(lblMAC)
	khCookie                = khProto.hash(lblCookie) //nolint:unused
	khBiscuitAdditionalData = khProto.hash(lblBiscuitAdditionalData)
	khPeerID                = khProto.hash(lblPeerID)
	khMix                   = khCKE.hash(lblMix)
	khOSK                   = khCKE.hash(lblUser, lblRosenpassEU, lblWireGuardPSK)
	khResEnc                = khCKE.hash(lblResponderHandshakeEncryption)
	khIniEnc                = khCKE.hash(lblInitiatorHandshakeEncryption)
	khHsEnc                 = khCKE.hash(lblHandshakeEncryption)
)
