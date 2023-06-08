// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package rosenpass

import (
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

type kemType = string

const (
	kemStatic    kemType = "Classic-McEliece-460896"
	kemEphemeral kemType = "Kyber512"
)

func generateStaticKeyPair() ([]byte, []byte, error) {
	if pk, sk, err := generateKeyPair(kemStatic); err != nil {
		return nil, nil, err
	} else {
		return spk(pk), ssk(sk), nil
	}
}

func generateEphemeralKeyPair() (epk, esk, error) {
	if pk, sk, err := generateKeyPair(kemEphemeral); err != nil {
		return nil, nil, err
	} else {
		return epk(pk), esk(sk), nil
	}
}

func generateKeyPair(alg kemType) ([]byte, []byte, error) {
	kem := &oqs.KeyEncapsulation{}
	if err := kem.Init(alg, nil); err != nil {
		return nil, nil, err
	}

	pk, err := kem.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	return pk, kem.ExportSecretKey(), nil
}

func newKEM(typ kemType, key []byte) (keyEncapsulation, error) {
	kem := &oqs.KeyEncapsulation{}
	if err := kem.Init(string(typ), key); err != nil {
		return nil, err
	}

	return kem, nil
}
