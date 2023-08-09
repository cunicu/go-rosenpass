// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/mceliece/mceliece460896"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	kemStatic    kem.Scheme = mceliece460896.Scheme()
	kemEphemeral kem.Scheme = kyber512.Scheme()
)

// GenerateKeyPair generates a new Classic McEliece key pair.
func GenerateKeyPair() (PublicKey, SecretKey, error) { //nolint:revive
	return generateStaticKeyPair()
}

// GenerateKeyPair generates a new Classic McEliece key pair in its old (round 2) format.
func GenerateRound2KeyPair() (PublicKey, SecretKey, error) { //nolint:revive
	spk, ssk, err := generateStaticKeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Convert a secret key from its round 3 to round 2 format
	if len(ssk) == sskSize {
		g := ssk[40:232]
		a := ssk[232:13032]
		s := ssk[13032:13608]

		sskNew := []byte{}
		sskNew = append(sskNew, s...)
		sskNew = append(sskNew, g...)
		sskNew = append(sskNew, a...)

		return spk, sskNew, nil
	}

	return spk, ssk, nil
}

// Generates a new pre-shared key.
func GeneratePresharedKey() (Key, error) { //nolint:revive
	k, err := generateKey(pskSize)
	if err != nil {
		return key{}, err
	}

	return key(k), nil
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

func generateSessionID() (sid, error) {
	s, err := generateKey(sidSize)
	if err != nil {
		return sid{}, err
	}

	return sid(s), nil
}

func generateNonce() (nonceX, error) {
	n, err := generateKey(nonceSizeX)
	if err != nil {
		return nonceX{}, err
	}

	return nonceX(n), nil
}

func generateBiscuitKey() (key, error) {
	n, err := generateKey(keySize)
	if err != nil {
		return key{}, err
	}

	return key(n), nil
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

func generateStaticKeyPair() (spk, ssk, error) {
	pk, sk, err := generateKeyPair(kemStatic)
	if err != nil {
		return nil, nil, err
	}

	return spk(pk), ssk(sk), nil
}

func generateEphemeralKeyPair() (epk, esk, error) {
	pk, sk, err := generateKeyPair(kemEphemeral)
	if err != nil {
		return nil, nil, err
	}

	return epk(pk), esk(sk), nil
}

func generateKeyPair(typ kem.Scheme) ([]byte, []byte, error) {
	pk, sk, err := typ.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	pk2, _ := pk.MarshalBinary()
	sk2, _ := sk.MarshalBinary()

	return pk2, sk2, nil
}

func newKEM(typ kem.Scheme, key []byte) (*keyEncapsulation, error) {
	return &keyEncapsulation{
		key:    key,
		scheme: typ,
	}, nil
}

type keyEncapsulation struct {
	scheme kem.Scheme
	key    []byte
}

func (ke *keyEncapsulation) EncapSecret(pk []byte) (ct []byte, ss []byte, err error) {
	cpk, err := ke.scheme.UnmarshalBinaryPublicKey(pk)
	if err != nil {
		return nil, nil, err
	}

	return ke.scheme.Encapsulate(cpk)
}

func (ke *keyEncapsulation) DecapSecret(ct []byte) (ss []byte, err error) {
	csk, err := ke.scheme.UnmarshalBinaryPrivateKey(ke.key)
	if err != nil {
		return nil, err
	}

	return ke.scheme.Decapsulate(csk, ct)
}
