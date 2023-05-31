// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import "time"

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

// Precompute keyed hash functions (kh*)
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

var (
	// Before Common Era (or more practically: Definitely so old it needs refreshing)
	//
	// Using this instead of Timing::MIN or Timing::INFINITY to avoid floating
	// point math weirdness.
	// BeforeCommonEra = 24 * 356 * 10000 * time.Hour

	// From the WireGuard paper
	// Rekey every two minutes, discard the key if no rekey is achieved within three
	RekeyAfterTimeResponder = 2 * time.Minute
	RekeyAfterTimeInitiator = RekeyAfterTimeResponder + 10*time.Second
	RejectAfterTime         = 3 * time.Minute

	// Seconds until the biscuit key is changed; we issue biscuits
	// using one biscuit key for one epoch and store the biscuit for
	// decryption for a second epoch
	BiscuitEpoch = 5 * time.Minute

	// Retransmission constants
	// will retransmit for up to 2 minutes; starting with a delay of
	// 0.5 seconds and increasing the delay exponentially by a factor of
	// 2 up to 10 seconds. An additional jitter factor of ±0.5 seconds is added.
	RetransmitDelayGrowth = 2.0
	RetransmitDelayBegin  = 500 * time.Millisecond
	RetransmitDelayEnd    = 10 * time.Second
	RetransmitDelayJitter = 500 * time.Millisecond
)
