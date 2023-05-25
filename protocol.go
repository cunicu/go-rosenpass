// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

// Precompute heyed hash functions (kh*)
var (
	khProto                 = key{}.hash(lblProtocol)
	khCKE                   = khProto.hash(lblChainingKeyExtract)
	khCKI                   = khProto.hash(lblChainingKeyInit)
	khMAC                   = khProto.hash(lblMAC)
	khCookie                = khProto.hash(lblCookie)
	khBiscuitAdditionalData = khProto.hash(lblBiscuitAdditionalData)
	khPeerID                = khProto.hash(lblPeerID)
	khMix                   = khCKE.hash(lblMix)
	khOSK                   = khCKE.hash(lblUser, lblRosenpass, lblWireGuardPSK)
	khResEnc                = khCKE.hash(lblResponderSessionEncryption)
	khIniEnc                = khCKE.hash(lblInitiatorSessionEncryption)
	khHsEnc                 = khCKE.hash(lblHandshakeEncryption)
)
