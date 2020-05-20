// Copyright 2020 The go-ethereum Authors
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

package rawdb

import (
	"bytes"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/youdb"
	"math/big"
	"testing"
)

func TestBlockStorage(t *testing.T) {
	db := youdb.NewMemDatabase()

	block := types.NewBlockWithHeader(&types.Header{
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
	})

	if entry := ReadBlock(db, block.Hash(), block.NumberU64()); entry != nil {
		t.Fatalf("Non existent block returned: %v", entry)
	}

	if entry := ReadHeader(db, block.Hash(), block.NumberU64()); entry != nil {
		t.Fatalf("Non existent header returned: %v", entry)
	}

	if entry := ReadBody(db, block.Hash(), block.NumberU64()); entry != nil {
		t.Fatalf("Non existent body returned: %v", entry)
	}

	WriteBlock(db, block)

	if entry := ReadBlock(db, block.Hash(), block.NumberU64()); entry == nil {
		t.Fatalf("Stored block not found")
	} else if entry.Hash() != block.Hash() {
		t.Fatalf("Retrieved block mismatch: have %v, want %v", entry, block)
	}
	if entry := ReadHeader(db, block.Hash(), block.NumberU64()); entry == nil {
		t.Fatalf("Stored header not found")
	} else if entry.Hash() != block.Header().Hash() {
		t.Fatalf("Retrieved header mismatch: have %v, want %v", entry, block.Header())
	}
	if entry := ReadBody(db, block.Hash(), block.NumberU64()); entry == nil {
		t.Fatalf("Stored body not found")
	} else if types.DeriveSha(types.Transactions(entry.Transactions)) != types.DeriveSha(block.Transactions()) {
		t.Fatalf("Retrieved body mismatch: have %v, want %v", entry, block.Body())
	}

	chtRoot := common.HexToHash("0x01020304")
	bltRoot := common.HexToHash("0x1112131415")
	acblock := types.NewBlock(&types.Header{
		TxHash:      types.EmptyRootHash,
		ReceiptHash: types.EmptyRootHash,
		Number:      big.NewInt(1),
		ChtRoot:     chtRoot.Bytes(),
		BltRoot:     bltRoot.Bytes(),
	}, nil, nil)

	WriteBlock(db, acblock)

	if entry := ReadBlock(db, acblock.Hash(), acblock.NumberU64()); entry == nil {
		t.Fatalf("Stored acblock not found")
	} else if entry.Hash() != acblock.Hash() {
		t.Fatalf("Retrieved acblock mismatch: have %v, want %v", entry, acblock)
	}
	if entry := ReadHeader(db, acblock.Hash(), acblock.NumberU64()); entry == nil {
		t.Fatalf("Stored header not found")
	} else {
		if entry.Hash() != acblock.Header().Hash() {
			t.Fatalf("Retrieved header mismatch: have %v, want %v", entry, acblock.Header())
		}
		if !bytes.Equal(entry.ChtRoot, chtRoot.Bytes()) {
			t.Fatalf("Retrieved ChtRoot in the header mismatch: have %x, want %x", entry.ChtRoot, chtRoot.Bytes())
		}
	}
	if entry := ReadBody(db, acblock.Hash(), acblock.NumberU64()); entry == nil {
		t.Fatalf("Stored body not found")
	} else {
		if types.DeriveSha(types.Transactions(entry.Transactions)) != types.DeriveSha(acblock.Transactions()) {
			t.Fatalf("Retrieved body mismatch: have %v, want %v", entry, acblock.Body())
		}
	}
}

func TestCanonicalStorage(t *testing.T) {
	db := youdb.NewMemDatabase()

	hash, number := common.Hash{0: 0xff}, uint64(314)
	if entry := ReadCanonicalHash(db, number); entry != (common.Hash{}) {
		t.Fatalf("non existent canonical mapping returned: %v", entry)
	}

	WriteCanonicalHash(db, hash, number)
	if entry := ReadCanonicalHash(db, number); entry == (common.Hash{}) {
		t.Fatalf("Stored canonical mapping not found")
	} else if entry != hash {
		t.Fatalf("Retrieved canonical mapping mismatch: have %v, want %v", entry, hash)
	}

	DeleteCanonicalHash(db, number)
	if entry := ReadCanonicalHash(db, number); entry != (common.Hash{}) {
		t.Fatalf("Deleted canonical mapping returned: %v", entry)
	}
}
