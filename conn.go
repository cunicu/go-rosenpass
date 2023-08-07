// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

type endpoint interface {
	String() string
	Equal(endpoint) bool
}

type receiveFunc func(spkm spk) (payload, endpoint, error)

type conn interface {
	Close() error
	Open() ([]receiveFunc, error)
	Send(pl payload, spkm spk, cep endpoint) error
}
