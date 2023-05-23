// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"crypto/cipher"
	"crypto/hmac"
	"hash"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	kemAlgStatic    = "Classic-McEliece-460896"
	kemAlgEphemeral = "Kyber512"
)

// A keyed hash function with one 32-byte input, one variable-size input, and one 32-byte output.
// As keyed hash function we use the HMAC construction with BLAKE2s as the inner hash function.
func Hash(key, data []byte, more ...[]byte) []byte {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key[:])

	mac.Write(data)

	h := mac.Sum(nil)

	if len(more) == 0 {
		return h
	}

	return Hash(h, more[0], more[1:]...)
}

func lhash(data []byte, more ...[]byte) []byte {
	return Hash(hashProtocol, data, more...)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

func newXAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key)
}

func newStaticKEM(key []byte) (*oqs.KeyEncapsulation, error) {
	kem := &oqs.KeyEncapsulation{}

	if err := kem.Init(kemAlgStatic, key); err != nil {
		return nil, err
	}

	return kem, nil
}

func newEphemeralKEM(key []byte) (*oqs.KeyEncapsulation, error) {
	kem := &oqs.KeyEncapsulation{}

	if err := kem.Init(kemAlgEphemeral, key); err != nil {
		return nil, err
	}

	return kem, nil
}

func generateKeyPair(alg string) ([]byte, []byte, error) {
	kem := &oqs.KeyEncapsulation{}
	if err := kem.Init(alg, nil); err != nil {
		return nil, nil, err
	}

	pk, err := kem.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	sk := kem.ExportSecretKey()

	return sk, pk, nil
}

func generateEphemeralKeyPair() (esk ephemeralPrivateKey, epk ephemeralPublicKey, err error) {
	sk, pk, err := generateKeyPair(kemAlgEphemeral)

	copy(esk[:], sk)
	copy(epk[:], pk)

	return
}

func generateStaticKeyPair() (ssk staticPrivateKey, spk staticPublicKey, err error) {
	sk, pk, err := generateKeyPair(kemAlgStatic)

	copy(ssk[:], sk)
	copy(spk[:], pk)

	return
}
