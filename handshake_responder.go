// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"encoding/binary"
	"fmt"
)

type responderHandshake struct {
	handshake
}

// Step 2.
func (hs *responderHandshake) handleInitHello(h *initHello) error {
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
	err := hs.decapAndMix(kemStatic, hs.server.sskm[:], hs.server.spkm[:], h.sctr[:])
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
		return fmt.Errorf("failed to lookup peer %s (IHR6): %w", pid(pidi), errPeerNotFound)
	}

	// IHR7: Ensure the responder has the correct view on spki. Mix in the PSK as optional
	//       static symmetric key, with epki and spkr serving as nonces.
	hs.mix(hs.peer.spkt[:], hs.peer.psk[:])

	// IHR8: Add a message authentication code to ensure both participants agree on the
	//       session state and protocol transcript at this point.
	if _, err := hs.decryptAndMix(h.auth[:]); err != nil {
		return fmt.Errorf("%w (IHR8): %w", errInvalidAuthTag, err)
	}

	return nil
}

// Step 3.
func (hs *responderHandshake) sendRespHello(from Endpoint) error {
	var err error

	// RHR1: Responder generates a session ID.
	if hs.sidr, err = generateSessionID(); err != nil {
		return fmt.Errorf("failed to generate session id (RHR1): %w", err)
	}

	// RHR3: Mix both session IDs as part of the protocol transcript.
	hs.mix(hs.sidr[:], hs.sidi[:])

	// RHR4: Key encapsulation using the ephemeral key, to provide forward secrecy.
	ecti, err := hs.encapAndMix(kemEphemeral, hs.epki[:])
	if err != nil {
		return fmt.Errorf("failed to encapsulate (RHR4): %w", err)
	}

	// RHR5: Key encapsulation using the initiator’s static key, to authenticate the
	//       initiator, and non-forward-secret confidentiality.
	scti, err := hs.encapAndMix(kemStatic, hs.peer.spkt[:])
	if err != nil {
		return fmt.Errorf("failed to encapsulate (RHR5): %w", err)
	}

	// RHR6: The responder transmits their state to the initiator in an encrypted container
	//       to avoid having to store state.
	biscuit, err := hs.storeBiscuit()
	if err != nil {
		return fmt.Errorf("failed to store biscuit (RHR6): %w", err)
	}

	// RHR7: Add a message authentication code for the same reason as above.
	auth, err := hs.encryptAndMix([]byte{})
	if err != nil {
		return fmt.Errorf("failed to encrypt and mix (RHR7): %w", err)
	}

	return hs.send(&respHello{
		sidr:    hs.sidr,
		sidi:    hs.sidi,
		ecti:    ect(ecti),
		scti:    sct(scti),
		biscuit: biscuit,
		auth:    authTag(auth),
	}, from)
}

// Step 6.
func (hs *responderHandshake) handleInitConf(i *initConf) error {
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
		return fmt.Errorf("%w (ICR4): %w", errInvalidAuthTag, err)
	}

	// ICR5: Biscuit replay detection.
	if !bNo.Larger(hs.peer.biscuitUsed) {
		return fmt.Errorf("%w (ICR5)", errReplayDetected)
	} else if bNo.Equal(hs.peer.biscuitUsed) {
		// This is a retransmitted InitConf message.
		// We skip ICR6 & ICR6 and just reply with EmptyData
		return nil
	}

	// ICR6: Biscuit replay detection.
	hs.peer.biscuitUsed = bNo

	// ICR7: Derive the transmission keys, and the output shared key for use as WireGuard’s PSK.
	hs.enterLive()

	return nil
}

// Step 7.
func (hs *responderHandshake) sendEmptyData(from Endpoint) error {
	hs.txnm++

	n := make([]byte, nonceSize)
	binary.LittleEndian.PutUint64(n, hs.txnm)

	aead, err := newAEAD(hs.txkm)
	if err != nil {
		return err
	}

	auth := aead.Seal(nil, n, []byte{}, []byte{})

	return hs.send(&emptyData{
		sid:  hs.sidi,
		ctr:  txNonce(n),
		auth: authTag(auth),
	}, from)
}

// Helpers

func (hs *responderHandshake) storeBiscuit() (sealedBiscuit, error) {
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

	pt := b.MarshalBinary(nil)

	xaead, err := newXAEAD(biscuitKey)
	if err != nil {
		return sealedBiscuit{}, err
	}

	ad := khBiscuitAdditionalData.hash(hs.server.spkm[:], hs.sidi[:], hs.sidr[:])
	nct := xaead.Seal(n[:], n[:], pt, ad[:])

	hs.mix(nct)

	return sealedBiscuit(nct), nil
}

func (hs *responderHandshake) loadBiscuit(sb sealedBiscuit) (biscuitNo, error) {
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
			return biscuitNo{}, errPeerNotFound
		}

		// assert(pt.biscuit_no ≤ peer.biscuit_used);
		if hs.peer.biscuitUsed.LargerOrEqual(b.biscuitNo) {
			return biscuitNo{}, errReplayDetected
		}

		// Restore the chaining key
		hs.ck = b.ck

		hs.mix(nct)

		// Expose the biscuit no,
		// so the handshake code can differentiate
		// retransmission requests and first time handshake completion
		return b.biscuitNo, nil
	}

	return biscuitNo{}, errInvalidBiscuit
}

func (hs *responderHandshake) enterLive() {
	hs.txkm = hs.ck.hash(khResEnc[:])
	hs.txkt = hs.ck.hash(khIniEnc[:])

	hs.handshake.enterLive()
}
