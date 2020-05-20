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

package core

import (
	"crypto/rand"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/trie"
	"github.com/youchainhq/go-youchain/youdb"
	"math/big"
	"os"
	"testing"
)

var size = 32768

func BenchmarkCHTIndexer(b *testing.B) {
	b.StopTimer()
	dbpath := "../ignores/testdb/"
	if _, err := os.Stat(dbpath); err == nil || !(os.IsNotExist(err)) {
		err := os.RemoveAll(dbpath)
		if err != nil {
			b.Fatal(err)
		}
	}
	db, err := youdb.NewLDBDatabase(dbpath, 0, 0)
	if err != nil {
		b.Fatal(err)
	}
	acindexer := newChtIndexerBackend(db, nil, uint64(size))
	err = acindexer.Reset(nil, 0, common.Hash{})
	if err != nil {
		b.Fatal(err)
	}
	hs := genHeaders(size)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		for _, h := range hs {
			err = acindexer.Process(nil, h)
			if err != nil {
				b.Fatal(err)
			}
		}
		err = acindexer.Commit()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBLTIndexer(b *testing.B) {
	b.StopTimer()
	dbpath := "../ignores/testdb/"
	if _, err := os.Stat(dbpath); err == nil || !(os.IsNotExist(err)) {
		err := os.RemoveAll(dbpath)
		if err != nil {
			b.Fatal(err)
		}
	}
	db, err := youdb.NewLDBDatabase(dbpath, 0, 0)
	if err != nil {
		b.Fatal(err)
	}
	acindexer := newBloomWithTrieIndexer(db, nil, uint64(size))
	err = acindexer.Reset(nil, 0, common.Hash{})
	if err != nil {
		b.Fatal(err)
	}
	hs := genHeaders(size)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		for _, h := range hs {
			err = acindexer.Process(nil, h)
			if err != nil {
				b.Fatal(err)
			}
		}
		err = acindexer.Commit()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func newChtIndexerBackend(db youdb.Database, chtFetcher MissingNodesFetcher, size uint64) *ChtIndexerBackend {
	trieTable := youdb.NewTable(db, ChtTablePrefix)
	cht := &ChtIndexerBackend{
		diskdb:      db,
		trieTable:   trieTable,
		mnFetcher:   chtFetcher,
		triedb:      trie.NewDatabase(trieTable),
		sectionSize: size,
	}
	return cht
}

func newBloomWithTrieIndexer(db youdb.Database, bltFetcher MissingNodesFetcher, size uint64) *BloomWithTrieIndexer {
	trieTable := youdb.NewTable(db, BloomTrieTablePrefix)
	blt := &BloomWithTrieIndexer{
		db:        db,
		size:      size,
		mnFetcher: bltFetcher,
		trieTable: trieTable,
		trieDb:    trie.NewDatabase(trieTable),
	}

	return blt
}

func genHeaders(size int) []*types.Header {
	hs := make([]*types.Header, 0, size)
	parentHash := common.Hash{}
	for i := 0; i < size; i++ {
		h := &types.Header{
			ParentHash:  parentHash,
			Coinbase:    common.Address{},
			Root:        randomHash(),
			TxHash:      randomHash(),
			ReceiptHash: randomHash(),
			Bloom:       randomBloom(),
			Number:      big.NewInt(int64(i)),
			GasLimit:    10000000,
			GasUsed:     1000000,
			GasRewards:  big.NewInt(10000),
			Subsidy:     big.NewInt(0),
			Time:        uint64(1574258600 + i),
			MixDigest:   common.Hash{},
			Extra:       []byte{},
			SlashData:   []byte{},
			Consensus:   []byte{},
			Validator:   []byte{},
			Signature:   []byte{},
			Certificate: []byte{},
		}
		parentHash = h.Hash()
		hs = append(hs, h)
	}
	return hs
}

func randomHash() common.Hash {
	h := common.Hash{}
	rand.Read(h[:]) //nolint:errcheck
	return h
}
func randomBloom() types.Bloom {
	b := types.Bloom{}
	rand.Read(b[:])
	return b
}
