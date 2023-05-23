// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import "encoding/binary"

func (n *biscuitNo) Inc(i uint64) {
	no := n.Load()
	no += i
	n.Store(no)
}

func (n *biscuitNo) Load() uint64 {
	return binary.BigEndian.Uint64(n[:])
}

func (n *biscuitNo) Store(m uint64) {
	binary.BigEndian.PutUint64(n[:], m)
}

func (n *biscuitNo) Larger(m biscuitNo) bool {
	return n.Load() > m.Load()
}
