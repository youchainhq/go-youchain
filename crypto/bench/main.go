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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/youchainhq/go-youchain/crypto/secp256k1"
	"io"
	"time"
)

const N = 20000

func main() {
	checkBeforeBench()
	benchmarkSign()
	benchmarkVerify()
}

func checkBeforeBench() {
	msg := csprngEntropy(32)
	pubkey, seckey := generateKeyPair()
	sig, err := secp256k1.Sign(msg, seckey)
	if err != nil {
		panic(err)
	}
	rpk, err := secp256k1.RecoverPubkey(msg, sig)
	if err != nil {
		panic(err)
	}
	if len(pubkey) != len(rpk) {
		panic(fmt.Errorf("pubkey mismatch, want len: %d got len: %d", len(pubkey), len(rpk)))
	}
	for i := range pubkey {
		if pubkey[i] != rpk[i] {
			panic(fmt.Errorf("pubkey mismatch, want: %x got: %x", pubkey, rpk))
		}
	}
}

func benchmarkSign() {
	_, seckey := generateKeyPair()
	msg := csprngEntropy(32)

	start := time.Now()
	for i := 0; i < N; i++ {
		secp256k1.Sign(msg, seckey)
	}
	d := time.Since(start)
	report("Sign  ", d)
}

func benchmarkVerify() {
	msg := csprngEntropy(32)
	_, seckey := generateKeyPair()
	sig, _ := secp256k1.Sign(msg, seckey)

	start := time.Now()
	for i := 0; i < N; i++ {
		secp256k1.RecoverPubkey(msg, sig)
	}
	d := time.Since(start)
	report("Verify", d)
}

func report(name string, d time.Duration) {
	p := d.Nanoseconds() / N
	fmt.Printf("%s\t%d\t%d ns/op\n", name, N, p)
}

func generateKeyPair() (pubkey, privkey []byte) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pubkey = elliptic.Marshal(secp256k1.S256(), key.X, key.Y)

	privkey = make([]byte, 32)
	blob := key.D.Bytes()
	copy(privkey[32-len(blob):], blob)

	return pubkey, privkey
}

func csprngEntropy(n int) []byte {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		panic("reading from crypto/rand failed: " + err.Error())
	}
	return buf
}
