// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"golang.org/x/exp/slog"
)

type initiatorHandshake struct {
	handshake

	nextMsg msgType // The type of the next expected message

	eski esk // The initiator’s ephemeral secret key

	expiryTimer  *time.Timer
	txTimer      *time.Timer
	txRetryCount uint

	biscuit sealedBiscuit
}

// Step 1.
func (hs *initiatorHandshake) sendInitHello() error {
	var err error

	// IHI1: Initialize the chaining key, and bind to the responder’s public key.
	hs.ck = khCKI.hash(hs.peer.spkt[:])

	// IHI2: The session ID is used to associate packets with the handshake state.
	if hs.sidi, err = generateSessionID(); err != nil {
		return err
	}

	// IHI3: Generate fresh ephemeral keys, for forward secrecy.
	if hs.epki, hs.eski, err = generateEphemeralKeyPair(); err != nil {
		return err
	}

	// IHI4: InitHello includes sidi and epki as part of the protocol transcript, and so we
	//       mix them into the chaining key to prevent tampering.
	hs.mix(hs.sidi[:], hs.epki[:])

	// IHI5: Key encapsulation using the responder’s public key. Mixes public key, shared
	//       secret, and ciphertext into the chaining key, and authenticates the responder.
	sctr, err := hs.encapAndMix(kemStatic, hs.peer.spkt[:])
	if err != nil {
		return err
	}

	// IHI6: Tell the responder who the initiator is by transmitting the peer ID.
	pidi := hs.server.PID()
	pidiC, err := hs.encryptAndMix(pidi[:])
	if err != nil {
		return err
	}

	// IHI7: Ensure the responder has the correct view on spki. Mix in the PSK as optional
	//       static symmetric key, with epki and spkr serving as nonces.
	hs.mix(hs.server.spkm[:], hs.peer.psk[:])

	// IHI8: Add a message authentication code to ensure both participants agree on the
	//       session state and protocol transcript at this point.
	auth, err := hs.encryptAndMix([]byte{})
	if err != nil {
		return err
	}

	hs.nextMsg = msgTypeRespHello

	return hs.send(&initHello{
		sidi:  hs.sidi,
		epki:  hs.epki,
		sctr:  sct(sctr),
		pidiC: [pidSize + authSize]byte(pidiC),
		auth:  authTag(auth),
	})
}

// Step 4.
func (hs *initiatorHandshake) handleRespHello(r *respHello) error {
	hs.biscuit = r.biscuit
	hs.sidr = r.sidr

	// RHI2: Initiator looks up their session state using the session ID they generated.
	// See: Server.handleEnvelope()

	// RHI3: Mix both session IDs as part of the protocol transcript.
	// TODO: Take local or exchanged ones?
	hs.mix(hs.sidr[:], hs.sidi[:])

	// RHI4: Key encapsulation using the ephemeral key, to provide forward secrecy.
	if err := hs.decapAndMix(kemEphemeral, hs.eski[:], hs.epki[:], r.ecti[:]); err != nil {
		return fmt.Errorf("failed to decapsulate (RHI4): %w", err)
	}

	// RHI5: Key encapsulation using the initiator’s static key, to authenticate the
	//       initiator, and non-forward-secret confidentiality.
	if err := hs.decapAndMix(kemStatic, hs.server.sskm[:], hs.server.spkm[:], r.scti[:]); err != nil {
		return fmt.Errorf("failed to decapsulate (RHI5): %w", err)
	}

	// RHI6: The responder transmits their state to the initiator in an encrypted container
	//       to avoid having to store state.
	hs.mix(r.biscuit[:])

	// RHI7: Add a message authentication code for the same reason as above.
	if _, err := hs.decryptAndMix(r.auth[:]); err != nil {
		return fmt.Errorf("%w (RHI7): %w", ErrInvalidAuthTag, err)
	}

	return nil
}

// Step 5.
func (hs *initiatorHandshake) sendInitConf() error {
	// ICI3: Mix both session IDs as part of the protocol transcript.
	hs.mix(hs.sidi[:], hs.sidr[:])

	// ICI4: Message authentication code for the same reason as above, which in particular
	//       ensures that both participants agree on the final chaining key.
	auth, err := hs.encryptAndMix([]byte{})
	if err != nil {
		return fmt.Errorf("failed to create authentication tag (ICI4): %w", err)
	}

	// ICI7: Derive the transmission keys, and the output shared key for use as WireGuard’s PSK.
	hs.enterLive()

	return hs.send(&initConf{
		sidi:    hs.sidi,
		sidr:    hs.sidr,
		biscuit: hs.biscuit,
		auth:    authTag(auth),
	})
}

// Step 8.
func (hs *initiatorHandshake) handleEmptyData(e *emptyData) error {
	n := append(e.ctr[:], 0, 0, 0, 0) //nolint:gocritic
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

	return nil
}

// Retransmission

func (hs *initiatorHandshake) retransmitDelay() time.Duration {
	after := RetransmitDelayBegin.Seconds() * math.Pow(RetransmitDelayGrowth, float64(hs.txRetryCount))
	if after > RetransmitDelayEnd.Seconds() {
		after = RetransmitDelayEnd.Seconds()
	}

	buf := make([]byte, 4)
	if n, err := rand.Read(buf); err == nil && n == 4 {
		irand := binary.LittleEndian.Uint32(buf)
		frand := float64(irand) / math.MaxUint32

		after += (2*frand - 1) * RetransmitDelayJitter.Seconds()
	}

	return time.Duration(after*1e6) * time.Microsecond
}

func (hs *initiatorHandshake) scheduleRetransmission(pl payload) {
	hs.txTimer = time.AfterFunc(hs.retransmitDelay(), func() {
		hs.txRetryCount++

		switch pl.(type) {
		case *initHello, *initConf: // Only InitHello and InitConf messages are retransmitted
			hs.scheduleRetransmission(pl)
		}

		if err := hs.server.conn.Send(pl, hs.peer.spkt, hs.peer.endpoint); err != nil {
			hs.peer.logger.Error("Failed to send", slog.Any("error", err))
		}
	})
}

func (hs *initiatorHandshake) send(pl payload) error {
	hs.txRetryCount = 0
	hs.scheduleRetransmission(pl)

	return hs.handshake.send(pl, hs.peer.endpoint)
}

// Helpers

func (hs *initiatorHandshake) enterLive() {
	hs.txkm = hs.ck.hash(khIniEnc[:])
	hs.txkt = hs.ck.hash(khResEnc[:])

	hs.handshake.enterLive()
}
