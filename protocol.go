// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package rosenpass

var (
	hashProtocol = hash(key{}, lblProtocol)

	cke    = lhash(lblChainingKeyExtract)
	cki    = lhash(lblChainingKeyInit)
	mix    = hash(cke, lblMix)
	osk    = hash(cke, lblUser, lblRosenpass, lblWireGuardPSK)
	resEnc = hash(cke, lblResponderSessionEncryption)
	iniEnc = hash(cke, lblInitiatorSessionEncryption)
	hsEnc  = hash(cke, lblHandshakeEncryption)
)
