// Copyright 2020 YOUCHAIN FOUNDATION LTD.
// This file is part of the go-youchain library.
//
// The go-youchain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-youchain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-youchain library. If not, see <http://www.gnu.org/licenses/>.

package ucon

import (
	"testing"

	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
)

func TestGetSignaturePublicKey(t *testing.T) {
	sk, _ := crypto.GenerateKey()
	//vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)

	payload := []byte{00001}

	// signature
	signature, _ := Sign(sk, payload)

	pk1, _ := GetSignaturePublicKey(payload, signature)
	pk2 := sk.PublicKey

	logging.Info("pk1", "x", pk1.X, "y", pk1.Y, "curve", pk1.Curve)
	logging.Info("pk2", "x", pk2.X, "y", pk2.Y, "curve", pk2.Curve)

	a1, _ := GetSignatureAddress(payload, signature)
	a2 := crypto.PubkeyToAddress(pk2)
	logging.Info("addr", "a1", a1)
	logging.Info("addr", "a2", a2)
}
