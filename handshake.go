// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"errors"
)

var (
	// TODO: Only expose errors which are need on the public API
	ErrUnexpectedMsgType = errors.New("received unexpected message type")
	ErrPeerNotFound      = errors.New("peer not found")
	ErrSessionNotFound   = errors.New("session not found")
	ErrInvalidAuthTag    = errors.New("invalid authentication tag")
	ErrReplayDetected    = errors.New("detected replay")
	ErrStaleNonce        = errors.New("stale nonce")
	ErrInvalidBiscuit    = errors.New("failed decrypt biscuit")
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

func (hs *handshake) encapAndMix(typ kemType, pk []byte) ([]byte, error) {
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

func (hs *handshake) decapAndMix(typ kemType, sk, pk, ct []byte) error {
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

func (hs *handshake) storeBiscuit() (sealedBiscuit, error) {
	hs.server.biscuitLock.Lock()
	hs.server.biscuitCtr.Inc()
	biscuitNo := hs.server.biscuitCtr
	biscuitKey := hs.server.biscuitKeys[0]
	hs.server.biscuitLock.Unlock()

	n, err := generateNonce()
	if err != nil {
		return sealedBiscuit{}, err
	}

	b := biscuit{
		biscuitNo: biscuitNo,
		pidi:      hs.peer.PID(),
		ck:        hs.ck,
	}

	pt := b.MarshalBinary()

	xaead, err := newXAEAD(biscuitKey)
	if err != nil {
		return sealedBiscuit{}, err
	}

	ad := khBiscuitAdditionalData.hash(hs.server.spkm[:], hs.sidi[:], hs.sidr[:])
	nct := xaead.Seal(n[:], n[:], pt, ad[:])

	hs.mix(nct)

	return sealedBiscuit(nct), nil
}

func (hs *handshake) loadBiscuit(sb sealedBiscuit) (biscuitNo, error) {
	nct := sb[:]
	n, ct := nct[:nonceSizeX], nct[nonceSizeX:]

	ad := khBiscuitAdditionalData.hash(hs.server.spkm[:], hs.sidi[:], hs.sidr[:])

	hs.server.biscuitLock.RLock()
	biscuitKeys := hs.server.biscuitKeys
	hs.server.biscuitLock.RUnlock()

	for _, k := range biscuitKeys {
		xaead, err := newXAEAD(k)
		if err != nil {
			return biscuitNo{}, err
		}

		pt, err := xaead.Open(nil, n, ct, ad[:])
		if err != nil {
			continue // Try next biscuit key
		}

		var b biscuit
		if _, err = b.UnmarshalBinary(pt); err != nil {
			return biscuitNo{}, err
		}

		// Find the peer and apply retransmission protection
		var ok bool
		if hs.peer, ok = hs.server.peers[b.pidi]; !ok {
			return biscuitNo{}, ErrPeerNotFound
		}

		// assert(pt.biscuit_no ≤ peer.biscuit_used);
		if hs.peer.biscuitUsed.LargerOrEqual(b.biscuitNo) {
			return biscuitNo{}, ErrReplayDetected
		}

		// Restore the chaining key
		hs.ck = b.ck

		hs.mix(nct)

		// Expose the biscuit no,
		// so the handshake code can differentiate
		// retransmission requests and first time handshake completion
		return b.biscuitNo, nil
	}

	return biscuitNo{}, ErrInvalidBiscuit
}

func (hs *handshake) send(pl payload) error {
	hs.peer.logger.Debug("Sending message", "type", msgTypeFromPayload(pl))

	return hs.server.conn.Send(pl, hs.peer)
}
