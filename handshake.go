// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"errors"
	"fmt"

	"golang.org/x/exp/slog"
)

var (
	ErrUnexpectedMsgType = errors.New("received unexpected message type")
	ErrPeerNotFound      = errors.New("peer not found")
	ErrSessionNotFound   = errors.New("session not found")
	ErrInvalidAuthTag    = errors.New("invalid authentication tag")
	ErrReplayDetected    = errors.New("detected replay")
)

type handshake struct {
	peer   *peer
	server *Server

	nextMsg msgType // The type of the next expected message

	sidi sid // Initiator session ID
	sidr sid // Responder session ID

	ck   key // The chaining key
	eski esk // The initiator’s ephemeral secret key
	epki epk // The initiator’s ephemeral public key
}

// Handshake phases

// Step 1
func (hs *handshake) sendInitHello() (*initHello, error) {
	var err error

	// IHI1: Initialize the chaining key, and bind to the responder’s public key.
	hs.ck = hash(cki, hs.peer.spkt[:])

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
	sctr, err := hs.encapsAndMix(kemAlgStatic, hs.peer.spkt[:])
	if err != nil {
		return nil, err
	}

	// IHI6: Tell the responder who the initiator is by transmitting the peer ID.
	pidi := hs.peer.PID()
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
	// IHR1: Initialize the chaining key, and bind to the responder’s public key.
	hs.ck = hash(cki, hs.peer.spkt[:])

	// IHR4: InitHello includes sidi and epki as part of the protocol transcript, and so we
	//       mix them into the chaining key to prevent tampering.
	hs.mix(h.sidi[:], h.epki[:])

	// IHR5: Key encapsulation using the responder’s public key. Mixes public key, shared
	//       secret, and ciphertext into the chaining key, and authenticates the responder.
	err := hs.decapsAndMix(kemAlgStatic, hs.server.sskm[:], hs.server.spkm[:], h.sctr[:])
	if err != nil {
		return err
	}

	// IHR6: Tell the responder who the initiator is by transmitting the peer ID.
	pidi, err := hs.decryptAndMix(h.pidiC[:])
	if err != nil {
		return fmt.Errorf("failed to decrypt peer id: %w", err)
	}

	var ok bool
	if hs.peer, ok = hs.server.peers[pid(pidi)]; !ok {
		return ErrPeerNotFound
	}

	// IHR7: Ensure the responder has the correct view on spki. Mix in the PSK as optional
	//       static symmetric key, with epki and spkr serving as nonces.
	hs.mix(hs.peer.spkt[:], hs.peer.psk[:])

	// IHR8: Add a message authentication code to ensure both participants agree on the
	//       session state and protocol transcript at this point.
	if _, err := hs.decryptAndMix(h.auth[:]); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAuthTag, err)
	}

	hs.nextMsg = msgTypeInitConf

	return nil
}

// Step 3
func (hs *handshake) sendRespHello() (*respHello, error) {
	var err error

	// RHR1: Responder generates a session ID.
	if hs.sidr, err = generateSessionID(); err != nil {
		return nil, err
	}

	// RHR3: Mix both session IDs as part of the protocol transcript.
	hs.mix(hs.sidr[:], hs.sidi[:])

	// RHR4: Key encapsulation using the ephemeral key, to provide forward secrecy.
	ecti, err := hs.encapsAndMix(kemAlgEphemeral, hs.epki[:])
	if err != nil {
		return nil, err
	}

	// RHR5: Key encapsulation using the initiator’s static key, to authenticate the
	//       initiator, and non-forward-secret confidentiality.
	scti, err := hs.encapsAndMix(kemAlgStatic, hs.peer.spkt[:])
	if err != nil {
		return nil, err
	}

	// RHR6: The responder transmits their state to the initiator in an encrypted container
	//       to avoid having to store state.
	biscuit, err := hs.storeBiscuit()
	if err != nil {
		return nil, err
	}

	// RHR7: Add a message authentication code for the same reason as above.
	auth, err := hs.encryptAndMix([]byte{})
	if err != nil {
		return nil, err
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
	// RHI2: Initiator looks up their session state using the session ID they generated.
	// See: Server.handleEnvelope()

	// RHI3: Mix both session IDs as part of the protocol transcript.
	// TODO: Take local or exchanged ones?
	hs.mix(r.sidr[:], r.sidi[:])

	// RHI4: Key encapsulation using the ephemeral key, to provide forward secrecy.
	if err := hs.decapsAndMix(kemAlgEphemeral, hs.eski[:], hs.epki[:], r.ecti[:]); err != nil {
		return err
	}

	// RHI5: Key encapsulation using the initiator’s static key, to authenticate the
	//       initiator, and non-forward-secret confidentiality.
	if err := hs.decapsAndMix(kemAlgStatic, hs.server.spkm[:], hs.server.spkm[:], r.scti[:]); err != nil {
		return err
	}

	// RHI6: The responder transmits their state to the initiator in an encrypted container
	//       to avoid having to store state.
	hs.mix(r.biscuit[:])

	// RHI7: Add a message authentication code for the same reason as above.
	if _, err := hs.decryptAndMix(r.auth[:]); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAuthTag, err)
	}

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
		return nil, fmt.Errorf("failed to create authentication tag")
	}

	// ICI7: Derive the transmission keys, and the output shared key for use as WireGuard’s PSK.
	hs.enterLive()

	return &initConf{
		sidi:    hs.sidi,
		sidr:    hs.sidr,
		biscuit: sealedBiscuit{}, // TODO
		auth:    authTag(auth),
	}, nil
}

// Step 6
func (hs *handshake) handleInitConf(i *initConf) error {
	// ICR1: Responder loads their biscuit. This restores the state from after RHR6.
	bNo, err := hs.loadBiscuit(i.biscuit)
	if err != nil {
		return fmt.Errorf("failed to load biscuit: %w", err)
	}

	// ICR2: Responder recomputes RHR7, since this step was performed after biscuit encoding.
	if _, err := hs.encryptAndMix([]byte{}); err != nil {
		return err
	}

	// ICR3: Mix both session IDs as part of the protocol transcript.
	hs.mix(hs.sidi[:], hs.sidr[:])

	// ICR4: Message authentication code for the same reason as above, which in particular
	//       ensures that both participants agree on the final chaining key.
	if _, err := hs.decryptAndMix(i.auth[:]); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidAuthTag, err)
	}

	// ICR5: Biscuit replay detection.
	if !bNo.Larger(hs.peer.biscuitUsed) {
		return ErrReplayDetected
	}

	// ICR6: Biscuit replay detection.
	hs.peer.biscuitUsed = bNo

	// ICR7: Derive the transmission keys, and the output shared key for use as WireGuard’s PSK.
	hs.enterLive()

	return nil
}

// Step 7
func (hs *handshake) sendEmptyData() (*emptyData, error) {
	return nil, nil
}

// Step 8
func (hs *handshake) handleEmptyData(e *emptyData) error {
	// TODO
	return nil
}

// Helpers

func (hs *handshake) enterLive() {
	hs.peer.logger.Debug("Entered live")

	if h, ok := hs.server.handler.(HandshakeHandler); ok {
		osk := hash(hs.ck, osk[:])
		hs.peer.logger.Debug("New key", slog.Any("osk", osk))

		h.HandshakeCompleted(hs.peer.PID(), osk)
	}
}

func (hs *handshake) mix(more ...[]byte) {
	hs.ck = hash(hs.ck, lblMix, more...) // TODO: wrong!
}

func (hs *handshake) encryptAndMix(pt []byte) ([]byte, error) {
	k := hash(hs.ck, hsEnc[:])
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
	k := hash(hs.ck, hsEnc[:])
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

func (hs *handshake) encapsAndMix(kemAlg string, pk []byte) ([]byte, error) {
	kem, err := newKEM(kemAlg, pk)
	if err != nil {
		return nil, err
	}

	ct, shk, err := kem.EncapSecret(pk)
	if err != nil {
		return nil, err
	}

	hs.mix(pk, ct, shk)

	return ct, nil
}

func (hs *handshake) decapsAndMix(kemAlg string, sk, pk, ct []byte) error {
	kem, err := newKEM(kemAlg, sk)
	if err != nil {
		return err
	}

	shk, err := kem.DecapSecret(ct)
	if err != nil {
		return err
	}

	hs.mix(pk, ct, shk)

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

	ad := lhash(lblBiscuitAdditionalData, hs.server.spkm[:], hs.peer.spkt[:], hs.sidi[:], hs.sidr[:])
	ct := xaead.Seal(nil, n[:], pt, ad[:])
	nct := append(n[:], ct...)

	hs.mix(nct)

	return sealedBiscuit(nct), nil
}

func (hs *handshake) loadBiscuit(nct sealedBiscuit) (biscuitNo, error) {
	k := hs.server.biscuitKeys[0]

	n, ct := nct[0:nonceSize], nct[nonceSize:]

	ad := lhash(lblBiscuitAdditionalData, hs.server.spkm[:], hs.sidi[:], hs.sidr[:])

	xaead, err := newXAEAD(k)
	if err != nil {
		return biscuitNo{}, err
	}

	pt, err := xaead.Open(k[:], n, ct, ad[:])
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

	if b.biscuitNo.Larger(hs.peer.biscuitUsed) {
		return biscuitNo{}, ErrReplayDetected
	}

	// Restore the chaining key
	hs.ck = b.ck

	hs.mix(nct[:])

	// Expose the biscuit no,
	// so the handshake code can differentiate
	// retransmission requests and first time handshake completion
	return b.biscuitNo, nil
}
