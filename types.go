// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"encoding/base64"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/exp/slog"
)

type msgType uint8

const (
	msgTypeInitHello msgType = iota + 0x81
	msgTypeRespHello
	msgTypeInitConf
	msgTypeEmptyData
)

func (t msgType) String() string {
	switch t {
	case msgTypeInitHello:
		return "InitHello"
	case msgTypeRespHello:
		return "RespHello"
	case msgTypeInitConf:
		return "InitConf"
	case msgTypeEmptyData:
		return "EmptyData"
	default:
		return "<Unknown>"
	}
}

const (
	hashSize = blake2s.Size

	sidSize = 4        // Session ID size
	pidSize = hashSize // Peer ID size

	keySize   = chacha20poly1305.KeySize
	authSize  = chacha20poly1305.Overhead // ChaCha20-Poly1305 authentication tag
	nonceSize = chacha20poly1305.NonceSizeX

	pskSize = hashSize // Pre-shared key size
	oskSize = hashSize // Output-shared key size
	ckSize  = hashSize // Chaining key size

	// Classic McEliece 460896
	sctSize = 188    // Static Cipher-text size
	spkSize = 524160 // Static public key size
	sskSize = 13568  // Static secret key size

	// Kyber-512
	ectSize = 768  // Ephemeral cipher text size
	epkSize = 800  // Ephemeral public key size
	eskSize = 1632 // Ephemeral secret key size

	// Envelope
	macSize      = 16
	cookieSize   = 16
	envelopeSize = 1 + 3 + macSize + cookieSize

	// Biscuit
	biscuitNoSize     = 12
	biscuitSize       = pidSize + biscuitNoSize + ckSize
	sealedBiscuitSize = biscuitSize + nonceSize + authSize

	initHelloMsgSize = sidSize + epkSize + sctSize + pidSize + 2*authSize
	respHelloMsgSize = 2*sidSize + ectSize + sctSize + biscuitSize + nonceSize + 2*authSize
	initConfMsgSize  = 2*sidSize + biscuitSize + nonceSize + 2*authSize
	emptyDataMsgSize = sidSize + 8 + authSize
)

type (
	biscuitNo [biscuitNoSize]byte

	authTag       [authSize]byte // Authentication tag
	cookie        [cookieSize]byte
	key           [keySize]byte
	psk           [pskSize]byte
	mac           [macSize]byte // Message authentication code
	nonce         [nonceSize]byte
	sid           [sidSize]byte // Session ID
	pid           [pidSize]byte // Peer ID
	sealedBiscuit [sealedBiscuitSize]byte

	sct []byte // Static Cipher-text
	spk []byte // Static public key
	ssk []byte // Static secret key
	ect []byte // Ephemeral cipher text size
	epk []byte // Ephemeral public key size
	esk []byte // Ephemeral secret key size
)

func (p *pid) LogValue() slog.Value {
	ps := base64.StdEncoding.EncodeToString(p[:])
	return slog.StringValue(ps)
}
