// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"time"

	"golang.org/x/exp/slog"
)

var (
	ErrUnexpectedMsgType = errors.New("received unexpected message type")
	ErrPeerNotFound      = errors.New("peer not found")
	ErrSessionNotFound   = errors.New("session not found")
	ErrInvalidAuthTag    = errors.New("invalid authentication tag")
	ErrReplayDetected    = errors.New("detected replay")
	ErrStaleNonce        = errors.New("stale nonce")
)

type role int

const (
	responder role = iota
	initiator
)

type handshake struct {
	server *Server
	peer   *peer

	role role

	nextMsg msgType // The type of the next expected message

	sidi sid // Initiator session ID
	sidr sid // Responder session ID

	ck   key // The chaining key
	eski esk // The initiator’s ephemeral secret key
	epki epk // The initiator’s ephemeral public key

	txnm uint64 // My transmission nonce
	txnt uint64 // Their transmission nonce

	txkm key // My transmission key
	txkt key // Their transmission key
	osk  key // Output shared key

	txPayload    payload
	txTimer      *time.Timer
	txRetryCount uint

	biscuit sealedBiscuit
}

// Handshake phases

// Step 1
func (hs *handshake) sendInitHello() (*initHello, error) {
	var err error

	// IHI1: Initialize the chaining key, and bind to the responder’s public key.
	hs.ck = khCKI.hash(hs.peer.spkt[:])

	// IHI2: The session ID is used to associate packets with the handshake state.
	if hs.sidi, err = generateSessionID(); err != nil {
		return nil, err
	}

	// IHI3: Generate fresh ephemeral keys, for forward secrecy.
	if hs.eski, hs.epki, err = generateKeyPair(kemAlgEphemeral); err != nil {
		return nil, err
	}

	// IHI4: InitHello includes sidi and epki as part of the protocol transcript, and so we
	//       mix them into the chaining key to prevent tampering.
	hs.mix(hs.sidi[:], hs.epki[:])

	// IHI5: Key encapsulation using the responder’s public key. Mixes public key, shared
	//       secret, and ciphertext into the chaining key, and authenticates the responder.
	sctr, err := hs.encapAndMix(kemAlgStatic, hs.peer.spkt[:])
	if err != nil {
		return nil, err
	}

	// IHI6: Tell the responder who the initiator is by transmitting the peer ID.
	pidi := hs.server.PID()
	pidiC, err := hs.encryptAndMix(pidi[:])
	if err != nil {
		return nil, err
	}

	// IHI7: Ensure the responder has the correct view on spki. Mix in the PSK as optional
	//       static symmetric key, with epki and spkr serving as nonces.
	hs.mix(hs.server.spkm[:], hs.peer.psk[:])

	// IHI8: Add a message authentication code to ensure both participants agree on the
	//       session state and protocol transcript at this point.
	auth, err := hs.encryptAndMix([]byte{})
	if err != nil {
		return nil, err
	}

	hs.nextMsg = msgTypeRespHello

	return &initHello{
		sidi:  hs.sidi,
		epki:  hs.epki,
		sctr:  sct(sctr),
		pidiC: [pidSize + authSize]byte(pidiC),
		auth:  authTag(auth),
	}, nil
}

// Step 2
func (hs *handshake) handleInitHello(h *initHello) error {
	// Keep some state for sendRespHello
	hs.epki = h.epki
	hs.sidi = h.sidi

	// IHR1: Initialize the chaining key, and bind to the responder’s public key.
	hs.ck = khCKI.hash(hs.server.spkm[:])

	// IHR4: InitHello includes sidi and epki as part of the protocol transcript, and so we
	//       mix them into the chaining key to prevent tampering.
	hs.mix(hs.sidi[:], hs.epki[:])

	// IHR5: Key encapsulation using the responder’s public key. Mixes public key, shared
	//       secret, and ciphertext into the chaining key, and authenticates the responder.
	err := hs.decapAndMix(kemAlgStatic, hs.server.sskm[:], hs.server.spkm[:], h.sctr[:])
	if err != nil {
		return fmt.Errorf("failed to decapsulate (IHR5): %w", err)
	}

	// IHR6: Tell the responder who the initiator is by transmitting the peer ID.
	pidi, err := hs.decryptAndMix(h.pidiC[:])
	if err != nil {
		return fmt.Errorf("failed to decrypt peer id (IHR6): %w", err)
	}

	var ok bool
	if hs.peer, ok = hs.server.peers[pid(pidi)]; !ok {
		return fmt.Errorf("failed to lookup peer %s (IHR6): %w", pid(pidi), ErrPeerNotFound)
	}

	// IHR7: Ensure the responder has the correct view on spki. Mix in the PSK as optional
	//       static symmetric key, with epki and spkr serving as nonces.
	hs.mix(hs.peer.spkt[:], hs.peer.psk[:])

	// IHR8: Add a message authentication code to ensure both participants agree on the
	//       session state and protocol transcript at this point.
	if _, err := hs.decryptAndMix(h.auth[:]); err != nil {
		return fmt.Errorf("%w (IHR8): %w", ErrInvalidAuthTag, err)
	}

	hs.nextMsg = msgTypeInitConf

	return nil
}

// Step 3
func (hs *handshake) sendRespHello() (*respHello, error) {
	var err error

	// RHR1: Responder generates a session ID.
	if hs.sidr, err = generateSessionID(); err != nil {
		return nil, fmt.Errorf("failed to generate session id (RHR1): %w", err)
	}

	// RHR3: Mix both session IDs as part of the protocol transcript.
	hs.mix(hs.sidr[:], hs.sidi[:])

	// RHR4: Key encapsulation using the ephemeral key, to provide forward secrecy.
	ecti, err := hs.encapAndMix(kemAlgEphemeral, hs.epki[:])
	if err != nil {
		return nil, fmt.Errorf("failed to encapsulate (RHR4): %w", err)
	}

	// RHR5: Key encapsulation using the initiator’s static key, to authenticate the
	//       initiator, and non-forward-secret confidentiality.
	scti, err := hs.encapAndMix(kemAlgStatic, hs.peer.spkt[:])
	if err != nil {
		return nil, fmt.Errorf("failed to encapsulate (RHR5): %w", err)
	}

	// RHR6: The responder transmits their state to the initiator in an encrypted container
	//       to avoid having to store state.
	biscuit, err := hs.storeBiscuit()
	if err != nil {
		return nil, fmt.Errorf("failed to store biscuit (RHR6): %w", err)
	}

	// RHR7: Add a message authentication code for the same reason as above.
	auth, err := hs.encryptAndMix([]byte{})
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt and mix (RHR7): %w", err)
	}

	return &respHello{
		sidr:    hs.sidr,
		sidi:    hs.sidi,
		ecti:    ect(ecti),
		scti:    sct(scti),
		biscuit: biscuit,
		auth:    authTag(auth),
	}, nil
}

// Step 4
func (hs *handshake) handleRespHello(r *respHello) error {
	hs.biscuit = r.biscuit
	hs.sidr = r.sidr

	// RHI2: Initiator looks up their session state using the session ID they generated.
	// See: Server.handleEnvelope()

	// RHI3: Mix both session IDs as part of the protocol transcript.
	// TODO: Take local or exchanged ones?
	hs.mix(hs.sidr[:], hs.sidi[:])

	// RHI4: Key encapsulation using the ephemeral key, to provide forward secrecy.
	if err := hs.decapAndMix(kemAlgEphemeral, hs.eski[:], hs.epki[:], r.ecti[:]); err != nil {
		return fmt.Errorf("failed to decapsulate (RHI4): %w", err)
	}

	// RHI5: Key encapsulation using the initiator’s static key, to authenticate the
	//       initiator, and non-forward-secret confidentiality.
	if err := hs.decapAndMix(kemAlgStatic, hs.server.sskm[:], hs.server.spkm[:], r.scti[:]); err != nil {
		return fmt.Errorf("failed to decapsulate (RHI5): %w", err)
	}

	// RHI6: The responder transmits their state to the initiator in an encrypted container
	//       to avoid having to store state.
	hs.mix(r.biscuit[:])

	// RHI7: Add a message authentication code for the same reason as above.
	if _, err := hs.decryptAndMix(r.auth[:]); err != nil {
		return fmt.Errorf("%w (RHI7): %w", ErrInvalidAuthTag, err)
	}

	hs.txTimer.Stop()

	return nil
}

// Step 5
func (hs *handshake) sendInitConf() (*initConf, error) {
	// ICI3: Mix both session IDs as part of the protocol transcript.
	hs.mix(hs.sidi[:], hs.sidr[:])

	// ICI4: Message authentication code for the same reason as above, which in particular
	//       ensures that both participants agree on the final chaining key.
	auth, err := hs.encryptAndMix([]byte{})
	if err != nil {
		return nil, fmt.Errorf("failed to create authentication tag (ICI4): %w", err)
	}

	// ICI7: Derive the transmission keys, and the output shared key for use as WireGuard’s PSK.
	hs.enterLive()

	return &initConf{
		sidi:    hs.sidi,
		sidr:    hs.sidr,
		biscuit: hs.biscuit,
		auth:    authTag(auth),
	}, nil
}

// Step 6
func (hs *handshake) handleInitConf(i *initConf) error {
	// Restore handshake state from message
	hs.sidi = i.sidi
	hs.sidr = i.sidr

	// ICR1: Responder loads their biscuit. This restores the state from after RHR6.
	bNo, err := hs.loadBiscuit(i.biscuit)
	if err != nil {
		return fmt.Errorf("failed to load biscuit (ICR1): %w", err)
	}

	// ICR2: Responder recomputes RHR7, since this step was performed after biscuit encoding.
	if _, err := hs.encryptAndMix([]byte{}); err != nil {
		return fmt.Errorf("failed to encrypt (ICR2): %w", err)
	}

	// ICR3: Mix both session IDs as part of the protocol transcript.
	hs.mix(hs.sidi[:], hs.sidr[:])

	// ICR4: Message authentication code for the same reason as above, which in particular
	//       ensures that both participants agree on the final chaining key.
	if _, err := hs.decryptAndMix(i.auth[:]); err != nil {
		return fmt.Errorf("%w (ICR4): %w", ErrInvalidAuthTag, err)
	}

	// ICR5: Biscuit replay detection.
	if !bNo.Larger(hs.peer.biscuitUsed) {
		return fmt.Errorf("%w (ICR5)", ErrReplayDetected)
	} else if bNo.Equal(hs.peer.biscuitUsed) {
		// This is a retransmitted InitConf message.
		// We skip ICR6 & ICR6 and just reply with EmptyData
		return nil
	}

	// ICR6: Biscuit replay detection.
	hs.peer.biscuitUsed = bNo

	// ICR7: Derive the transmission keys, and the output shared key for use as WireGuard’s PSK.
	hs.enterLive()

	hs.peer.logger.Debug("Handshake completed")

	for _, h := range hs.server.handlers {
		h.HandshakeCompleted(hs.peer.PID(), hs.osk)
	}

	return nil
}

// Step 7
func (hs *handshake) sendEmptyData() (*emptyData, error) {
	hs.txnm++

	n := make([]byte, nonceSize)
	binary.LittleEndian.PutUint64(n, hs.txnm)

	aead, err := newAEAD(hs.txkm)
	if err != nil {
		return nil, err
	}

	auth := aead.Seal(nil, n, []byte{}, []byte{})

	return &emptyData{
		sid:  hs.sidi,
		ctr:  txNonce(n),
		auth: authTag(auth),
	}, nil
}

// Step 8
func (hs *handshake) handleEmptyData(e *emptyData) error {
	n := append(e.ctr[:], 0, 0, 0, 0)
	txnt := binary.LittleEndian.Uint64(e.ctr[:])

	// TODO: Check nonce counter
	if txnt < hs.txnt {
		return ErrStaleNonce
	}
	hs.txnt = txnt

	aead, err := newAEAD(hs.txkt)
	if err != nil {
		return err
	}

	if _, err := aead.Open(nil, n, e.auth[:], []byte{}); err != nil {
		return ErrInvalidAuthTag
	}

	hs.peer.logger.Debug("Handshake completed")

	for _, h := range hs.server.handlers {
		h.HandshakeCompleted(hs.peer.PID(), hs.osk)
	}

	hs.txTimer.Stop()

	return nil
}

// Helpers

func (hs *handshake) enterLive() {
	hs.txnm = 0
	hs.txnt = 0
	hs.osk = hs.ck.hash(khOSK[:])

	if hs.role == responder {
		hs.txkm = hs.ck.hash(khResEnc[:])
		hs.txkt = hs.ck.hash(khIniEnc[:])
	} else {
		hs.txkm = hs.ck.hash(khIniEnc[:])
		hs.txkt = hs.ck.hash(khResEnc[:])
	}

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

func (hs *handshake) encapAndMix(kemAlg string, pk []byte) ([]byte, error) {
	kem, err := newKEM(kemAlg, pk)
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

func (hs *handshake) decapAndMix(kemAlg string, sk, pk, ct []byte) error {
	kem, err := newKEM(kemAlg, sk)
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
	hs.server.biscuitCtr.Inc(1)

	k := hs.server.biscuitKeys[0]

	n, err := generateNonce()
	if err != nil {
		return sealedBiscuit{}, err
	}

	b := biscuit{
		biscuitNo: hs.server.biscuitCtr,
		pidi:      hs.peer.PID(),
		ck:        hs.ck,
	}

	pt := b.MarshalBinary()

	xaead, err := newXAEAD(k)
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
	k := hs.server.biscuitKeys[0]
	n, ct := nct[:nonceSizeX], nct[nonceSizeX:]
	ad := khBiscuitAdditionalData.hash(hs.server.spkm[:], hs.sidi[:], hs.sidr[:])

	xaead, err := newXAEAD(k)
	if err != nil {
		return biscuitNo{}, err
	}

	pt, err := xaead.Open(nil, n, ct, ad[:])
	if err != nil {
		return biscuitNo{}, err
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

// Retransmission

func (hs *handshake) scheduleRetransmission() {
	after := RetransmitDelayBegin

	after += time.Duration(math.Pow(RetransmitDelayGrowth, float64(hs.txRetryCount)))
	if after > RetransmitDelayEnd {
		after = RetransmitDelayEnd
	}

	after += time.Duration((2*rand.Float64() - 1) * float64(RetransmitDelayJitter))

	hs.txTimer = time.AfterFunc(after, func() {
		hs.txRetryCount++

		if err := hs.send(hs.txPayload); err != nil {
			hs.peer.logger.Error("Failed to send", slog.Any("error", err))
		}
	})
}

func (hs *handshake) send(pl payload) error {
	hs.peer.logger.Debug("Sending message", "type", msgTypeFromPayload(pl))

	if hs.txTimer != nil {
		hs.txTimer.Stop()
	}

	hs.txPayload = pl
	hs.txRetryCount = 0

	switch pl.(type) {
	// Only InitHello and InitConf messages are retransmitted
	case *initHello, *initConf:
		hs.scheduleRetransmission()
	}

	return hs.server.conn.Send(pl, hs.peer)
}
