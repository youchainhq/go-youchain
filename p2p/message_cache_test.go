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

package p2p

import (
	"github.com/youchainhq/go-youchain/crypto"
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	cache := MessageCacheInstance()

	key1 := crypto.Keccak256Hash([]byte("0x08"))

	cache.AddMsg(key1)
	if cache.Check(key1) {
		t.Logf("key %s is exist", key1.String())
	} else {
		panic("not finde")
	}

	key2 := crypto.Keccak256Hash([]byte("0x09"))
	if !cache.Check(key2) {
		t.Logf("key %s not exist", key2.String())
	} else {
		panic("exist")
	}

	time.Sleep(5 * time.Second)
}
