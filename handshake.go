// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"errors"

	"github.com/cloudflare/circl/kem"
)

var (
	// TODO: Only expose errors which are need on the public API.
	errUnexpectedMsgType = errors.New("received unexpected message type")
	errPeerNotFound      = errors.New("peer not found")
	errSessionNotFound   = errors.New("session not found")
	errInvalidAuthTag    = errors.New("invalid authentication tag")
	errReplayDetected    = errors.New("detected replay")
	errStaleNonce        = errors.New("stale nonce")
	errInvalidBiscuit    = errors.New("failed decrypt biscuit")
)

type handshake struct {
	peer   *peer
	server *Server

	sidi sid // Initiator session ID
	sidr sid // Responder session ID

	ck   key // The chaining key
	epki epk // The initiator’s ephemeral public key

	txnm uint64 // My transmission nonce
	txnt uint64 // Their transmission nonce

	txkm key // My transmission key
	txkt key // Their transmission key
	osk  key // Output shared key
}

// Helpers

func (hs *handshake) enterLive() {
	hs.txnm = 0
	hs.txnt = 0
	hs.osk = hs.ck.hash(khOSK[:])

	hs.peer.logger.Debug("Enter live")
}

func (hs *handshake) mix(data ...[]byte) {
	hs.ck = hs.ck.mix(data...)
}

func (hs *handshake) encryptAndMix(pt []byte) ([]byte, error) {
	k := hs.ck.hash(khHsEnc[:])
	n := nonce{}
	ad := []byte{}

	aead, err := newAEAD(k)
	if err != nil {
		return nil, err
	}

	ct := aead.Seal(nil, n[:], pt, ad)

	hs.mix(ct)

	return ct, nil
}

func (hs *handshake) decryptAndMix(ct []byte) ([]byte, error) {
	k := hs.ck.hash(khHsEnc[:])
	n := nonce{}
	ad := []byte{}

	aead, err := newAEAD(k)
	if err != nil {
		return nil, err
	}

	pt, err := aead.Open(nil, n[:], ct, ad)
	if err != nil {
		return nil, err
	}

	hs.mix(ct)

	return pt, nil
}

func (hs *handshake) encapAndMix(typ kem.Scheme, pk []byte) ([]byte, error) {
	kem, err := newKEM(typ, pk)
	if err != nil {
		return nil, err
	}

	ct, shk, err := kem.EncapSecret(pk)
	if err != nil {
		return nil, err
	}

	hs.mix(pk, shk, ct)

	return ct, nil
}

func (hs *handshake) decapAndMix(typ kem.Scheme, sk, pk, ct []byte) error {
	kem, err := newKEM(typ, sk)
	if err != nil {
		return err
	}

	shk, err := kem.DecapSecret(ct)
	if err != nil {
		return err
	}

	hs.mix(pk, shk, ct)

	return nil
}

func (hs *handshake) send(pl Payload, ep Endpoint) error {
	hs.peer.logger.Debug("Sending message", "type", msgTypeFromPayload(pl))

	return hs.server.conn.Send(pl, hs.peer.spkt, ep)
}
