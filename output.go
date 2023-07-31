// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type KeyOutputReason string

const (
	KeyOutputReasonExchanged KeyOutputReason = "exchanged"
	KeyOutputReasonStale     KeyOutputReason = "stale"
)

// Output format:
// output-key peer {} key-file {of:?} {why}
type KeyOutput struct {
	Peer    PeerID
	KeyFile string
	Why     KeyOutputReason
}

func ParseKeyOutput(str string) (o KeyOutput, err error) {
	tokens := strings.Split(str, " ")

	if tokens[0] != "output-key" ||
		tokens[1] != "peer" ||
		tokens[3] != "key-file" {
		return o, errors.New("invalid output format")
	}

	if o.Peer, err = ParsePeerID(tokens[2]); err != nil {
		return o, fmt.Errorf("failed to parse peer id: %w", err)
	}

	o.KeyFile = strings.Trim(tokens[4], "\"")
	o.Why = KeyOutputReason(tokens[5])

	return o, nil
}

func (o KeyOutput) String() string {
	return strings.Join([]string{
		"output-key",
		"peer", o.Peer.String(),
		"key-file", strconv.Quote(o.KeyFile),
		string(o.Why),
	}, " ")
}
