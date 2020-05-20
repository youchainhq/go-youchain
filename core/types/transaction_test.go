// Copyright 2020 YOUCHAIN FOUNDATION LTD.
// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"bytes"
	"crypto/ecdsa"
	"github.com/stretchr/testify/assert"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/rlp"
	"math/big"
	"testing"
)

var (
	emptyTx = NewTransaction(
		0,
		common.HexToAddress("0xa94f5374Fce5edBC8E2a8697C15331677e6EbF0B"),
		big.NewInt(0),
		0,
		big.NewInt(0),
		nil)
)

func DefaultTestKey() (*ecdsa.PrivateKey, common.Address) {
	key, _ := crypto.HexToECDSA("45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8")
	addr := crypto.PubkeyToAddress(key.PublicKey)
	return key, addr
}

func TestReallySmall(t *testing.T) {
	b, _ := new(big.Int).SetString("0.1", 10)
	assert.Nil(t, b)
}

func TestTransactionEncodeRLP(t *testing.T) {
	txb, err := rlp.EncodeToBytes(emptyTx)
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	should := common.FromHex("dd80808094a94f5374fce5edbc8e2a8697c15331677e6ebf0b8080808080")
	if !bytes.Equal(txb, should) {
		t.Fatalf("encode RLP missmatch, got %x", txb)
	}
}

func TestTransactionDecodeRLP(t *testing.T) {
	var tx Transaction
	err := rlp.DecodeBytes(common.Hex2Bytes("dd80808094a94f5374fce5edbc8e2a8697c15331677e6ebf0b8080808080"), &tx)
	if err != nil {
		t.Fatal("decode error")
	}

	if !bytes.Equal(tx.To().Bytes(), common.FromHex("0xa94f5374Fce5edBC8E2a8697C15331677e6EbF0B")) {
		t.Fatalf("decode RLP missmatch get %+v", tx)
	}
}
