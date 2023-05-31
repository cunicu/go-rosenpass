// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import "encoding/binary"

func (n *biscuitNo) Inc(i uint64) {
	no := n.Load()
	no += i
	n.Store(no)
}

// TODO: Extend to full 96bit space
func (n *biscuitNo) Load() uint64 {
	return binary.LittleEndian.Uint64(n[:])
}

// TODO: Extend to full 96bit space
func (n *biscuitNo) Store(m uint64) {
	binary.LittleEndian.PutUint64(n[:], m)
}

func (n *biscuitNo) Equal(m biscuitNo) bool {
	return n.Load() == m.Load()
}

func (n *biscuitNo) Larger(m biscuitNo) bool {
	return n.Load() > m.Load()
}

func (n *biscuitNo) LargerOrEqual(m biscuitNo) bool {
	return n.Load() >= m.Load()
}
