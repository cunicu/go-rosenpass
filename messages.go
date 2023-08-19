// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"crypto/subtle"
	"errors"
)

var (
	errMsgTruncated   = errors.New("message is truncated")
	errInvalidLen     = errors.New("invalid message length")
	errInvalidMsgType = errors.New("invalid message type")
	errInvalidMAC     = errors.New("invalid mac")
)

type Payload interface {
	MarshalBinary(buf []byte) []byte
	UnmarshalBinary(buf []byte) (int, error)
}

type Envelope struct {
	typ     msgType // Type of this message
	payload Payload // The actual payload
	mac     mac     // Message Authentication Code (mac) over all bytes until (exclusive) mac itself
	cookie  cookie  // Currently unused, TODO: do something with this
}

func (e *Envelope) MarshalBinaryAndSeal(spkt spk, buf []byte) []byte {
	buf = e.MarshalBinary(buf)

	macOffset := len(buf) - macSize - cookieSize
	macKey := khMAC.hash(spkt[:], buf[:macOffset])

	copy(buf[macOffset:], macKey[:macSize])

	return buf
}

func (e *Envelope) CheckAndUnmarshalBinary(buf []byte, spkm spk) (int, error) {
	if len(buf) < envelopeSize {
		return -1, errMsgTruncated
	}

	macOffset := len(buf) - macSize - cookieSize
	macWire := buf[macOffset : macOffset+macSize]
	macKey := khMAC.hash(spkm[:], buf[:macOffset])
	macCalc := macKey[:macSize]

	if subtle.ConstantTimeCompare(macWire, macCalc) != 1 {
		return -1, errInvalidMAC
	}

	return e.UnmarshalBinary(buf)
}

func (e *Envelope) MarshalBinary(buf []byte) []byte {
	mTyp := msgTypeFromPayload(e.payload)

	buf = append(buf, uint8(mTyp), 0, 0, 0)
	buf = e.payload.MarshalBinary(buf)

	return concat(buf,
		e.mac[:],
		e.cookie[:])
}

func (e *Envelope) UnmarshalBinary(buf []byte) (o int, err error) {
	lenPayload := len(buf) - envelopeSize
	if lenPayload <= 0 {
		return -1, errMsgTruncated
	}

	switch msgType(buf[0]) {
	case msgTypeInitHello:
		e.payload = &initHello{}
	case msgTypeRespHello:
		e.payload = &respHello{}
	case msgTypeInitConf:
		e.payload = &initConf{}
	case msgTypeEmptyData:
		e.payload = &emptyData{}
	default:
		return -1, errInvalidMsgType
	}

	o += 4

	p, err := e.payload.UnmarshalBinary(buf[o : o+lenPayload])
	if err != nil {
		return -1, err
	}

	o += p
	o += copy(e.mac[:], buf[o:])
	o += copy(e.cookie[:], buf[o:])

	return o, nil
}

type biscuit struct {
	pidi      pid       // hash(spki) – Identifies the initiator
	biscuitNo biscuitNo // The biscuit number (replay protection)
	ck        key       // Chaining key
}

func (b *biscuit) MarshalBinary(buf []byte) []byte {
	return concat(buf,
		b.pidi[:],
		b.biscuitNo[:],
		b.ck[:])
}

func (b *biscuit) UnmarshalBinary(buf []byte) (o int, err error) {
	if len(buf) != biscuitSize {
		return -1, errInvalidLen
	}

	o += copy(b.pidi[:], buf[o:])
	o += copy(b.biscuitNo[:], buf[o:])
	o += copy(b.ck[:], buf[o:])

	return o, nil
}

type initHello struct {
	sidi  sid                      // Randomly generated connection id
	epki  epk                      // Kyber 512 Ephemeral Public Key
	sctr  sct                      // Classic McEliece Ciphertext
	pidiC [pidSize + authSize]byte // Encryped: 16 byte hash of McEliece initiator static key
	auth  authTag                  // Encrypted TAI64N Time Stamp (against replay attacks)
}

func (m *initHello) MarshalBinary(buf []byte) []byte {
	return concat(buf,
		m.sidi[:],
		m.epki[:],
		m.sctr[:],
		m.pidiC[:],
		m.auth[:])
}

func (m *initHello) UnmarshalBinary(buf []byte) (o int, err error) {
	if len(buf) != initHelloMsgSize {
		return -1, errInvalidLen
	}

	o += copy(m.sidi[:], buf[o:])

	m.epki = epk(buf[o:])
	o += epkSize
	m.sctr = sct(buf[o:])
	o += sctSize

	o += copy(m.pidiC[:], buf[o:])
	o += copy(m.auth[:], buf[o:])

	return o, nil
}

type respHello struct {
	sidr    sid           // Randomly generated connection id
	sidi    sid           // Copied from InitHello
	ecti    ect           // Kyber 512 Ephemeral Ciphertext
	scti    sct           // Classic McEliece Ciphertext
	biscuit sealedBiscuit // Responders handshake state in encrypted form
	auth    authTag       // Empty encrypted message (just an auth tag)
}

func (m *respHello) MarshalBinary(buf []byte) []byte {
	return concat(buf,
		m.sidr[:],
		m.sidi[:],
		m.ecti[:],
		m.scti[:],
		m.auth[:],
		m.biscuit[:])
}

func (m *respHello) UnmarshalBinary(buf []byte) (o int, err error) {
	if len(buf) != respHelloMsgSize {
		return -1, errInvalidLen
	}

	o += copy(m.sidr[:], buf[o:])
	o += copy(m.sidi[:], buf[o:])

	m.ecti = ect(buf[o:])
	o += ectSize
	m.scti = sct(buf[o:])
	o += sctSize

	o += copy(m.auth[:], buf[o:])
	o += copy(m.biscuit[:], buf[o:])

	return o, nil
}

type initConf struct {
	sidi    sid           // Copied from InitHello
	sidr    sid           // Copied from RespHello
	biscuit sealedBiscuit // Responders handshake state in encrypted form
	auth    authTag       // Empty encrypted message (just an auth tag)
}

func (m *initConf) MarshalBinary(buf []byte) []byte {
	return concat(buf,
		m.sidi[:],
		m.sidr[:],
		m.biscuit[:],
		m.auth[:])
}

func (m *initConf) UnmarshalBinary(buf []byte) (o int, err error) {
	if len(buf) != initConfMsgSize {
		return -1, errInvalidLen
	}

	o += copy(m.sidi[:], buf[o:])
	o += copy(m.sidr[:], buf[o:])
	o += copy(m.biscuit[:], buf[o:])
	o += copy(m.auth[:], buf[o:])

	return o, nil
}

type emptyData struct {
	sid  sid     // Copied from RespHello
	ctr  txNonce // Nonce
	auth authTag // Empty encrypted message (just an auth tag)
}

func (m *emptyData) MarshalBinary(buf []byte) []byte {
	return concat(buf,
		m.sid[:],
		m.ctr[:],
		m.auth[:])
}

func (m *emptyData) UnmarshalBinary(buf []byte) (o int, err error) {
	if len(buf) != emptyDataMsgSize {
		return -1, errInvalidLen
	}

	o += copy(m.sid[:], buf[o:])
	o += copy(m.ctr[:], buf[o:])
	o += copy(m.auth[:], buf[o:])

	return o, nil
}

func concat(buf []byte, parts ...[]byte) []byte {
	for _, part := range parts {
		buf = append(buf, part...)
	}

	return buf
}
