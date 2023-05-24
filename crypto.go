// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	hashpkg "hash"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	kemAlgStatic    = "Classic-McEliece-460896"
	kemAlgEphemeral = "Kyber512"
)

// Generate a new Classic McEliece key pair
func GenerateKeyPair() (ssk ssk, spk spk, err error) {
	return generateKeyPair(kemAlgStatic)
}

// A keyed hash function with one 32-byte input, one variable-size input, and one 32-byte output.
// As keyed hash function we use the HMAC construction with BLAKE2s as the inner hash function.
func hash(key key, data []byte, more ...[]byte) [hashSize]byte {
	mac := hmac.New(func() hashpkg.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key[:])

	mac.Write(data)

	h := [hashSize]byte(mac.Sum(nil))

	if len(more) == 0 {
		return h
	}

	return hash(h, more[0], more[1:]...)
}

func lhash(data []byte, more ...[]byte) [hashSize]byte {
	return hash(hashProtocol, data, more...)
}

func newAEAD(k key) (cipher.AEAD, error) {
	return chacha20poly1305.New(k[:])
}

func newXAEAD(k key) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(k[:])
}

func newKEM(alg string, key []byte) (*oqs.KeyEncapsulation, error) {
	kem := &oqs.KeyEncapsulation{}

	if err := kem.Init(alg, key); err != nil {
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

func generateSessionID() (sid, error) {
	i := make([]byte, sidSize)

	if n, err := rand.Read(i); err != nil {
		return sid{}, err
	} else if n != sidSize {
		return sid{}, errors.New("partial read")
	}

	return sid(i), nil
}

func generateNonce() (nonce, error) {
	n := make([]byte, nonceSize)

	if n, err := rand.Read(n); err != nil {
		return nonce{}, err
	} else if n != nonceSize {
		return nonce{}, fmt.Errorf("partial read")
	}

	return nonce(n), nil
}
