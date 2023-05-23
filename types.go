// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"crypto/rand"
	"errors"
	"fmt"
)

type msgType uint8

const (
	msgTypeInitHello msgType = iota + 0x81
	msgTypeRespHello
	msgTypeInitConf
	msgTypeEmptyData
)

const (
	hashSize  = 32
	authSize  = 16
	nonceSize = 24

	sessionIDSize = 4
	peerIDSize    = hashSize

	presharedKeySize    = 32
	outputSharedKeySize = hashSize
	chainingKeySize     = hashSize

	// Classic McEliece 460896
	staticCipherTextSize = 188
	staticPublicKeySize  = 524160
	staticPrivateKeySize = 13568

	//  Kyber-512
	ephemeralCipherTextSize = 768
	ephemeralPublicKeySize  = 800
	ephemeralPrivateKeySize = 1632

	// Envelope
	macSize      = 16
	cookieSize   = 16
	envelopeSize = 1 + 3 + macSize + cookieSize

	// Biscuit
	ciscuitNoSize     = 12
	biscuitSize       = peerIDSize + ciscuitNoSize + chainingKeySize
	sealedBiscuitSize = biscuitSize + nonceSize + authSize

	initHelloSize = sessionIDSize + ephemeralPublicKeySize + staticCipherTextSize + peerIDSize + 2*authSize
	respHelloSize = 2*sessionIDSize + ephemeralCipherTextSize + staticCipherTextSize + biscuitSize + nonceSize + 2*authSize
	initConfSize  = 2*sessionIDSize + biscuitSize + nonceSize + 2*authSize
	emptyDataSize = sessionIDSize + 8 + authSize
)

type (
	sessionID   [sessionIDSize]byte
	peerID      [peerIDSize]byte
	hasht       [hashSize]byte
	nonce       [nonceSize]byte
	chainingKey [chainingKeySize]byte

	staticCipherText [staticCipherTextSize]byte
	staticPublicKey  [staticPublicKeySize]byte
	staticPrivateKey [staticPrivateKeySize]byte

	ephemeralCipherText [ephemeralCipherTextSize]byte
	ephemeralPublicKey  [ephemeralPublicKeySize]byte
	ephemeralPrivateKey [ephemeralPrivateKeySize]byte

	authTag [authSize]byte
	mac     [macSize]byte
	cookie  [cookieSize]byte
)

func generateSessionID() (sessionID, error) {
	i := make([]byte, 4)

	if n, err := rand.Read(i); err != nil {
		return sessionID{}, err
	} else if n != 4 {
		return sessionID{}, errors.New("failed to generate ID")
	}

	return *(*sessionID)(i), nil
}

func generateRandomNonce() ([]byte, error) {
	nonce := make([]byte, 24)

	if n, err := rand.Read(nonce); err != nil {
		return nil, err
	} else if n != 24 {
		return nil, fmt.Errorf("incomplete read")
	}

	return nonce, nil
}
