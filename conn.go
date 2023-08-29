// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

type Endpoint interface {
	String() string
	Equal(Endpoint) bool
}

type ReceiveFunc func(spkm spk) (payload, Endpoint, error)

type Conn interface {
	Close() error
	Open() ([]ReceiveFunc, error)
	Send(pl payload, spkm spk, cep Endpoint) error
}
