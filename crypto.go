// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"golang.org/x/crypto/blake2b"
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

// Generates a new pre-shared key
func GeneratePresharedKey() (key, error) {
	if k, err := generateKey(pskSize); err != nil {
		return key{}, err
	} else {
		return key(k), nil
	}
}

func blake2(k key, d []byte) key {
	h, _ := blake2b.New256(k[:])
	h.Write(d)
	return key(h.Sum(nil))
}

func hmac(k key, d []byte) key {
	var iKey, oKey key
	for i := range iKey {
		iKey[i] = k[i] ^ 0x36
		oKey[i] = k[i] ^ 0x5c
	}

	outer := blake2(iKey, d)
	return blake2(oKey, outer[:])
}

// A keyed hmac function with one 32-byte input, one variable-size input, and one 32-byte output.
// As keyed hmac function we use the HMAC construction with BLAKE2s as the inner hmac function.
func (k key) hash(data ...[]byte) key {
	for _, d := range data {
		k = hmac(k, d)
	}
	return k
}

func (k key) mix(data ...[]byte) key {
	for _, d := range data {
		k = k.hash(khMix[:], d)
	}
	return k
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
	if s, err := generateKey(sidSize); err != nil {
		return sid{}, err
	} else {
		return sid(s), nil
	}
}

func generateNonce() (nonceX, error) {
	if n, err := generateKey(nonceSizeX); err != nil {
		return nonceX{}, err
	} else {
		return nonceX(n), nil
	}
}

func generateKey(l int) ([]byte, error) {
	p := make([]byte, l)

	if n, err := rand.Read(p); err != nil {
		return nil, err
	} else if n != l {
		return nil, fmt.Errorf("partial read")
	}

	return p, nil
}
