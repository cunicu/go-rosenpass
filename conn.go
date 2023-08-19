// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

type Endpoint interface {
	String() string
	Equal(Endpoint) bool
}

type ReceiveFunc func(spkm spk, buf []byte) (Payload, Endpoint, error)

type Conn interface {
	Close() error
	Open() ([]ReceiveFunc, error)
	Send(pl Payload, spkm spk, cep Endpoint) error
}
