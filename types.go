// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"encoding/base64"
	"encoding/hex"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

type msgType uint8

const (
	msgTypeInitHello msgType = iota + 0x81
	msgTypeRespHello
	msgTypeInitConf
	msgTypeEmptyData
	msgTypeData
	msgTypeCookieReply
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

func msgTypeFromPayload(pl payload) msgType {
	switch pl.(type) {
	case *initHello:
		return msgTypeInitHello
	case *respHello:
		return msgTypeRespHello
	case *initConf:
		return msgTypeInitConf
	case *emptyData:
		return msgTypeEmptyData
	default:
		return 0
	}
}

const (
	hashSize = blake2b.Size256

	sidSize = 4        // Session ID size
	pidSize = hashSize // Peer ID size

	keySize     = chacha20poly1305.KeySize
	authSize    = chacha20poly1305.Overhead // ChaCha20-Poly1305 authentication tag
	nonceSize   = chacha20poly1305.NonceSize
	nonceSizeX  = chacha20poly1305.NonceSizeX
	txNonceSize = 8 // Nonce for live sessions

	pskSize = hashSize // Pre-shared key size
	oskSize = hashSize // Output-shared key size
	ckSize  = hashSize // Chaining key size

	// Classic McEliece 460896 sizes.
	sctSize       = 188    // Static Cipher-text size
	spkSize       = 524160 // Static public key size
	sskSizeRound2 = 13568  // Static secret key size (Round 2 implementation)
	sskSize       = 13608  // Static secret key size

	// Kyber-512 sizes.
	ectSize = 768  // Ephemeral cipher text size
	epkSize = 800  // Ephemeral public key size
	eskSize = 1632 // Ephemeral secret key size

	// Envelope sizes.
	macSize      = 16
	cookieSize   = 16
	envelopeSize = 4 + macSize + cookieSize

	// Biscuit sizes.
	biscuitNoSize     = 12
	biscuitSize       = pidSize + biscuitNoSize + ckSize
	sealedBiscuitSize = biscuitSize + nonceSizeX + authSize

	initHelloMsgSize = sidSize + epkSize + sctSize + pidSize + 2*authSize
	respHelloMsgSize = 2*sidSize + ectSize + sctSize + biscuitSize + nonceSizeX + 2*authSize
	initConfMsgSize  = 2*sidSize + biscuitSize + nonceSizeX + 2*authSize
	emptyDataMsgSize = sidSize + 8 + authSize
)

type (
	biscuitNo [biscuitNoSize]byte

	authTag       [authSize]byte // Authentication tag
	key           [keySize]byte
	cookie        [cookieSize]byte
	mac           [macSize]byte // Message authentication code
	nonce         [nonceSize]byte
	nonceX        [nonceSizeX]byte
	txNonce       [txNonceSize]byte
	sid           [sidSize]byte // Session ID
	pid           [pidSize]byte // Peer ID
	sealedBiscuit [sealedBiscuitSize]byte

	sct []byte // Static Cipher-text
	spk []byte // Static public key
	ssk []byte // Static secret key
	ect []byte // Ephemeral cipher text size
	epk []byte // Ephemeral public key size
	esk []byte // Ephemeral secret key size

	// Some aliases for the public API.
	PeerID = pid

	PresharedKey = key
	PublicKey    = spk
	SecretKey    = ssk
	Key          = key
)

func ParsePeerID(s string) (pid, error) { //nolint:revive
	p, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return pid{}, err
	}

	return pid(p), nil
}

func (p pid) String() string {
	return base64.StdEncoding.EncodeToString(p[:])
}

func (s sid) String() string {
	return hex.EncodeToString(s[:])
}

func (k key) String() string {
	t, _ := k.MarshalText() //nolint:errcheck
	return string(t)
}

func (k *key) UnmarshalText(text []byte) error {
	_, err := base64.StdEncoding.Decode(k[:], text)
	return err
}

func (k key) MarshalText() (text []byte, err error) {
	b := make([]byte, base64.StdEncoding.EncodedLen(keySize))
	base64.StdEncoding.Encode(b, k[:])
	return b, nil
}
