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
	"bytes"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto/sha3"
	"github.com/youchainhq/go-youchain/rlp"
	"io/ioutil"
	"testing"
	"time"
)

func TestMsg_Hash(t *testing.T) {
	content := []byte("Hello, World")
	reader := bytes.NewReader(content)
	msg := Msg{
		Code:       1,
		Size:       uint32(len(content)),
		Payload:    reader,
		ReceivedAt: time.Now(),
	}

	p1, err := rlp.EncodeToBytes(msg.Code)
	if err != nil {
		t.Fatal("rlp.EncodeToBytes", err)
	}

	key1 := bytes.NewBuffer(p1)
	key1.Write(content)

	sha1 := sha3.NewKeccak256()
	sha1.Write(key1.Bytes())
	hash1 := sha1.Sum(nil)

	checkSum1 := common.BytesToHash(hash1)

	checkSum2 := msg.Hash()

	if ok := bytes.Equal(checkSum1.Bytes(), checkSum2.Bytes()); !ok {
		t.Fatalf("hash1 = %x, hash2 = %x", checkSum1, checkSum2)
	}

	t.Logf("hash1 = %x, hash2 = %x", checkSum1, checkSum2)

	payload, _ := ioutil.ReadAll(msg.Payload)

	if ok := bytes.Equal(payload, content); !ok {
		t.Fatalf("buf = %s, content = %s", payload, content)
	}
	t.Logf("buf = %s, content = %s", payload, content)
}
