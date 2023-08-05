// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build !cgo

package rosenpass

import (
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/mceliece/mceliece460896"
)

type kemType = kem.Scheme

var (
	kemStatic    kemType = mceliece460896.Scheme()
	kemEphemeral kemType = kyber512.Scheme()
)

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

func newKEM(typ kemType, key []byte) (keyEncapsulation, error) {
	return &circlKeyEncapsulation{
		key:    key,
		scheme: typ,
	}, nil
}

type circlKeyEncapsulation struct {
	scheme kem.Scheme
	key    []byte
}

func (ke *circlKeyEncapsulation) EncapSecret(pk []byte) (ct []byte, ss []byte, err error) {
	cpk, err := ke.scheme.UnmarshalBinaryPublicKey(pk)
	if err != nil {
		return nil, nil, err
	}

	return ke.scheme.Encapsulate(cpk)
}

func (ke *circlKeyEncapsulation) DecapSecret(ct []byte) (ss []byte, err error) {
	csk, err := ke.scheme.UnmarshalBinaryPrivateKey(ke.key)
	if err != nil {
		return nil, err
	}

	return ke.scheme.Decapsulate(csk, ct)
}
