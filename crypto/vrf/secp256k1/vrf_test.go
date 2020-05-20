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

package secp256k1VRF

import (
	"fmt"
	"github.com/youchainhq/go-youchain/crypto"
	"reflect"
	"testing"
)

var (
	priKey = `a7a758b38db731a6210eabd11265185de192fb9df317341adc808db155997ffb`
)

func TestVrf(t *testing.T) {
	sk, pk := GenerateKey()

	m := []byte{0x1}
	v0, proof := sk.Evaluate(m)

	v1, err := pk.ProofToHash(m, proof)

	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(v0, v1) {
		t.Fatal("expect equal, got different", fmt.Sprintf("%x", v0), fmt.Sprintf("%x", v1))
	}
}

func TestGeneratedPriKey(t *testing.T) {
	ecdsaSk, _ := crypto.HexToECDSA(priKey)
	sk, _ := NewVRFSigner(ecdsaSk)

	pk, _ := NewVRFVerifier(&ecdsaSk.PublicKey)
	m := []byte{0x1}
	v0, proof := sk.Evaluate(m)

	v1, err := pk.ProofToHash(m, proof)

	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(v0, v1) {
		t.Fatal("expect equal, got different", fmt.Sprintf("%x", v0), fmt.Sprintf("%x", v1))
	}
}

func BenchmarkPrivateKey_Evaluate(b *testing.B) {
	m := make([]byte, 40)
	for i := 0; i < 40; i++ {
		m[i] = byte(i)
	}
	sk, _ := GenerateKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.Evaluate(m)
	}
}

func BenchmarkPublicKey_ProofToHash(b *testing.B) {
	m := make([]byte, 40)
	for i := 0; i < 40; i++ {
		m[i] = byte(i)
	}
	sk, pk := GenerateKey()
	_, proof := sk.Evaluate(m)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.ProofToHash(m, proof)
	}
}
