// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"errors"
)

var (
	ErrMsgTruncated = errors.New("message is truncated")
	ErrInvalidLen   = errors.New("invalid message length")
	ErrWrongMsgType = errors.New("wrong message type")
)

type payload interface {
	MarshalBinary() []byte
	UnmarshalBinary(data []byte) (int, error)
}

type envelope struct {
	// [MsgType] of this message
	typ msgType

	// The actual payload
	payload payload

	// Message Authentication Code (mac) over all bytes until (exclusive) mac itself
	mac mac

	// Currently unused, TODO: do something with this
	cookie cookie
}

func (e *envelope) MarshalBinary() (data []byte, err error) {
	pl, err := e.MarshalBinary()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, len(pl)+36)

	// var mtype msgType
	// switch e.Payload.(type) {
	// case *InitHello:
	// 	mtype = msgTypeInitHello
	// case *RespHello:
	// 	mtype = msgTypeRespHello
	// case *InitConf:
	// 	mtype = msgTypeInitConf
	// case *EmptyData:
	// 	mtype = msgTypeEmptyData
	// }

	// buf[0] = uint8(mtype)
	// copy(buf[4:], pl)
	// copy(buf[4+len(pl):], e.MAC)
	// copy(buf[4+len(pl)+16:], e.Cookie)

	return buf, nil
}

func (e *envelope) UnmarshalBinary(buf []byte) (int, error) {
	if len(buf) < envelopeSize {
		return -1, ErrMsgTruncated
	}

	mtype := msgType(buf[0])

	switch mtype {
	case msgTypeInitHello:
		e.payload = &initHello{}
	case msgTypeRespHello:
		e.payload = &respHello{}
	case msgTypeInitConf:
		e.payload = &initConf{}
	case msgTypeEmptyData:
		e.payload = &emptyData{}
	default:
		return -1, ErrWrongMsgType
	}

	o := 4

	if p, err := e.payload.UnmarshalBinary(buf[o:]); err != nil {
		return -1, err
	} else {
		o += p
	}

	if o+32 > len(buf[o:]) {
		return -1, ErrMsgTruncated
	}

	o += copy(e.mac[:], buf[o:])
	o += copy(e.cookie[:], buf[o:])

	return o, nil
}

type biscuit struct {
	// Hash(spki) – Identifies the initiator
	pidi peerID

	// The biscuit number (replay protection)
	biscuitNo [12]byte

	// Chaining key
	ck chainingKey
}

func (b *biscuit) MarshalBinary() []byte {
	return concat(biscuitSize,
		b.pidi[:],
		b.biscuitNo[:],
		b.ck[:])
}

func (b *biscuit) UnmarshalBinary(buf []byte) (int, error) {
	if len(buf) != biscuitSize {
		return -1, ErrInvalidLen
	}

	o := copy(b.pidi[:], buf)
	o += copy(b.biscuitNo[:], buf[o:])
	o += copy(b.ck[:], buf[o:])

	return o, nil
}

type sealedBiscuit struct {
	data [biscuitSize]byte

	nonce nonce
	auth  authTag
}

func (b *sealedBiscuit) MarshalBinary() []byte {
	return concat(sealedBiscuitSize,
		b.data[:],
		b.nonce[:],
		b.auth[:])
}

func (b *sealedBiscuit) UnmarshalBinary(buf []byte) (int, error) {
	if len(buf) != sealedBiscuitSize {
		return -1, ErrInvalidLen
	}

	o := copy(b.data[:], buf)
	o += copy(b.nonce[:], buf[o:])
	o += copy(b.auth[:], buf[o:])

	return o, nil
}

type initHello struct {
	// Randomly generated connection id
	sidi sessionID

	// Kyber 512 Ephemeral Public Key
	epki ephemeralPublicKey

	// Classic McEliece Ciphertext
	sctr staticCipherText

	// Encryped: 16 byte hash of McEliece initiator static key
	pidiC [peerIDSize + authSize]byte

	// Encrypted TAI64N Time Stamp (against replay attacks)
	auth authTag
}

func (m *initHello) MarshalBinary() []byte {
	return concat(initHelloSize,
		m.sidi[:],
		m.epki[:],
		m.sctr[:],
		m.pidiC[:],
		m.auth[:])
}

func (m *initHello) UnmarshalBinary(buf []byte) (int, error) {
	if len(buf) != initHelloSize {
		return -1, ErrInvalidLen
	}

	o := copy(m.sidi[:], buf)
	o += copy(m.epki[:], buf[o:])
	o += copy(m.sctr[:], buf[o:])
	o += copy(m.pidiC[:], buf[o:])
	o += copy(m.auth[:], buf[o:])

	return o, nil
}

type respHello struct {
	// Randomly generated connection id
	sidr sessionID

	// Copied from InitHello
	sidi sessionID

	// Kyber 512 Ephemeral Ciphertext
	ecti ephemeralCipherText

	// Classic McEliece Ciphertext
	scti staticCipherText

	// Empty encrypted message (just an auth tag)
	auth authTag

	// Responders handshake state in encrypted form
	biscuit sealedBiscuit
}

func (m *respHello) MarshalBinary() []byte {
	return concat(respHelloSize,
		m.sidr[:],
		m.sidi[:],
		m.ecti[:],
		m.scti[:],
		m.biscuit.MarshalBinary(),
		m.auth[:])
}

func (m *respHello) UnmarshalBinary(buf []byte) (int, error) {
	if len(buf) != respHelloSize {
		return -1, ErrInvalidLen
	}

	o := copy(m.sidr[:], buf)
	o += copy(m.sidi[:], buf[o:])
	o += copy(m.ecti[:], buf[o:])
	o += copy(m.scti[:], buf[o:])

	if p, err := m.biscuit.UnmarshalBinary(buf[o : o+sealedBiscuitSize]); err != nil {
		return -1, err
	} else {
		o += p
	}

	o += copy(m.auth[:], buf[o:])

	return o, nil
}

type initConf struct {
	// Copied from InitHello
	sidi sessionID

	// Copied from RespHello
	sidr sessionID

	// Responders handshake state in encrypted form
	biscuit sealedBiscuit

	// Empty encrypted message (just an auth tag)
	auth authTag
}

func (m *initConf) MarshalBinary() []byte {
	return concat(initConfSize,
		m.sidi[:],
		m.sidr[:],
		m.biscuit.MarshalBinary(),
		m.auth[:])
}

func (m *initConf) UnmarshalBinary(buf []byte) (int, error) {
	if len(buf) != initConfSize {
		return -1, ErrInvalidLen
	}

	o := copy(m.sidi[:], buf)
	o += copy(m.sidr[:], buf[o:])

	if p, err := m.biscuit.UnmarshalBinary(buf[o : o+sealedBiscuitSize]); err != nil {
		return -1, err
	} else {
		o += p
	}

	o += copy(m.auth[:], buf[o:])

	return o, nil
}

type emptyData struct {
	// Copied from RespHello
	sid sessionID

	// Nonce
	ctr [8]byte

	// Empty encrypted message (just an auth tag)
	auth authTag
}

func (m *emptyData) MarshalBinary() []byte {
	return concat(emptyDataSize,
		m.sid[:],
		m.ctr[:],
		m.auth[:])
}

func (m *emptyData) UnmarshalBinary(buf []byte) (int, error) {
	if len(buf) != emptyDataSize {
		return -1, ErrInvalidLen
	}

	o := copy(m.sid[:], buf)
	o += copy(m.ctr[:], buf[o:])
	o += copy(m.auth[:], buf[o:])

	return o, nil
}

func concat(length int, parts ...[]byte) []byte {
	buf := make([]byte, 0, length)

	for _, part := range parts {
		buf = append(buf, part...)
	}

	if len(buf) != length {
		panic("failed to construct msg")
	}

	return buf
}
