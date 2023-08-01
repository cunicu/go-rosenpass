// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import "encoding/hex"

// Inc increments the biscuit counter by one in constant time
// The byte ordering is little endian.
func (n *biscuitNo) Inc() {
	c := uint16(1)
	for i := 0; i < biscuitNoSize; i++ {
		c += uint16(n[i])
		n[i] = byte(c)
		c >>= 8
	}
}

// String returns a string representation of the biscuit counter in hex-notation.
func (n *biscuitNo) String() string {
	return hex.EncodeToString(n[:])
}

// Equal compares the biscuit counters in constant time and returns true if they are equal.
func (n *biscuitNo) Equal(m biscuitNo) bool {
	return n.Compare(m) == 0
}

// Larger compares the biscuit counters in constant time and returns true if it is larger than the supplied one.
func (n *biscuitNo) Larger(m biscuitNo) bool {
	return n.Compare(m) == 1
}

// Lesser compares the biscuit counters in constant time and returns true if it lesser than the supplied one.
func (n *biscuitNo) Lesser(m biscuitNo) bool {
	return n.Compare(m) == -1
}

// LargerOrEqual compares the biscuit counters in constant time and returns true if it larger or equal than the supplied one.
func (n *biscuitNo) LargerOrEqual(m biscuitNo) bool {
	return n.Compare(m) >= 0
}

// Compare compares the biscuit counters in constant time.
func (n *biscuitNo) Compare(m biscuitNo) int {
	var gt byte
	var eq byte = 1

	i := biscuitNoSize
	for i != 0 {
		i--
		x1 := uint16(n[i])
		x2 := uint16(m[i])
		gt |= byte((x2-x1)>>8) & eq
		eq &= byte(((x2 ^ x1) - 1) >> 8)
	}

	return (int)(gt+gt+eq) - 1
}
