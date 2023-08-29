// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

func RosenpassFilterEbpf(lPort int) asm.Instructions {
	return asm.Instructions{
		// LoadAbs() requires ctx in R6
		asm.Mov.Reg(asm.R6, asm.R1),

		// Offset of transport header from start of packet
		// IPv6 raw sockets do not include the network layer
		// so this is 0 by default
		asm.LoadImm(asm.R7, 0, asm.DWord),

		// r1 has ctx
		// r0 = ctx[16] (aka protocol)
		asm.LoadMem(asm.R0, asm.R1, 16, asm.Word),

		// Perhaps IPv6? Then skip the IPv4 part..
		asm.LoadImm(asm.R2, int64(unix.ETH_P_IPV6), asm.DWord),
		asm.HostTo(asm.BE, asm.R2, asm.Half),
		asm.JEq.Reg(asm.R0, asm.R2, "load"),

		// Transport layer starts after 20 Byte IPv4 header
		// TODO: use IHL field to account for IPv4 options
		asm.LoadImm(asm.R7, 20, asm.DWord),

		// Load UDP destination port
		asm.LoadInd(asm.R0, asm.R7, 2, asm.Half).WithSymbol("load"),

		// Skip if is not matching our listen port
		asm.JNE.Imm(asm.R0, int32(lPort), "skip"),

		// Load WireGuard packet type
		asm.LoadInd(asm.R0, asm.R7, 8, asm.Byte),

		// Skip if the packet type is lower than 0x81 (is a WireGuard packet)
		asm.JLT.Imm(asm.R0, 0x81, "skip"),

		asm.Mov.Imm(asm.R0, -1).WithSymbol("exit"),
		asm.Return(),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("skip"),
		asm.Return(),
	}
}
