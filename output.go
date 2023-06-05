// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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

func ScanKeyOutput(rd io.Reader) (o KeyOutput, err error) {
	scanner := bufio.NewScanner(rd)

	for scanner.Scan() {
		tokens := strings.Split(scanner.Text(), " ")

		if tokens[0] != "output-key" ||
			tokens[1] != "peer" ||
			tokens[3] != "key-file" {
			return o, errors.New("invalid output format")
		}

		if o.Peer, err = ParsePeerID(tokens[2]); err != nil {
			return o, fmt.Errorf("failed to parse peer id: %w", err)
		}

		o.KeyFile = tokens[4]
		o.Why = KeyOutputReason(tokens[5])

		break //nolint:staticcheck
	}

	return o, nil
}

func (o KeyOutput) Dump(wr io.Writer) (int, error) {
	return fmt.Fprintf(wr, "output-key peer %s key-file %s %s\n", o.Peer, o.KeyFile, o.Why)
}
