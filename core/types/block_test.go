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
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
)

var (
	emptyBlock = NewBlock(&Header{
		Coinbase:    common.Address{},
		Number:      big.NewInt(0),
		GasRewards:  big.NewInt(0),
		Subsidy:     big.NewInt(0),
		ParentHash:  EmptyRootHash,
		TxHash:      EmptyRootHash,
		ReceiptHash: EmptyRootHash}, Transactions{emptyTx}, nil)
)

func TestEmptyRootHash(t *testing.T) {
	logging.Info("TestEmptyRootHash", "EmptyRootHash", EmptyRootHash.String())
	t1 := DeriveSha(Transactions{})
	e1 := DeriveSha(Receipts{})

	logging.Info("TestEmptyRootHash", "EmptyTxsHash", t1.String())
	logging.Info("TestEmptyRootHash", "EmptyReceiptsHash", e1.String())
}

func TestBlockEncoding(t *testing.T) {
	fmt.Printf("%s,%s\n", emptyBlock.header.Hash().String(), emptyBlock.Hash().String())

	enc, err := rlp.EncodeToBytes(emptyBlock)
	if err != nil {
		t.Fatal("encode error")
	}

	var block Block
	if err := rlp.DecodeBytes(enc, &block); err != nil {
		t.Fatal("decode error", err)
	}

	check := func(f string, got, want interface{}) {
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s mismatch: got %v, want %v", f, got, want)
		}
	}

	check("Coinbase", block.Coinbase(), common.Address{})
	check("Tx", emptyTx.Hash(), block.Transactions()[0].Hash())
}

func TestHeader_Size(t *testing.T) {
	h := &Header{
		Coinbase:    common.Address{},
		Number:      big.NewInt(0),
		GasRewards:  big.NewInt(0),
		Subsidy:     big.NewInt(0),
		ParentHash:  EmptyRootHash,
		TxHash:      EmptyRootHash,
		ReceiptHash: EmptyRootHash,
	}
	fmt.Println(h.Size())
}

func TestDeriveSha(t *testing.T) {
	var r Receipts
	h := DeriveSha(r)
	t.Log(h.String())
	var rs []*Receipt
	r = Receipts(rs)
	h = DeriveSha(r)
	t.Log(h.String())
}

func TestHeader_MarshalJSON(t *testing.T) {
	h := emptyBlock.Header()
	h.CurrVersion = params.YouCurrentVersion
	j, err := h.MarshalJSON()
	require.NoError(t, err)
	t.Log(string(j))
	var h2 Header
	err = json.Unmarshal(j, &h2)
	require.NoError(t, err)
}
