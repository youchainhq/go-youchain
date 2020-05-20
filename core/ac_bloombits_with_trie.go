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
	"context"
	"encoding/binary"
	"fmt"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/bloombits"
	"github.com/youchainhq/go-youchain/core/rawdb"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/trie"
	"github.com/youchainhq/go-youchain/youdb"
	"time"
)

const (
	// bloomThrottling is the time to wait between processing two consecutive index
	// sections. It's useful during chain upgrades to prevent disk overload.
	bloomThrottling = 100 * time.Millisecond
)

var (
	BloomTrieTablePrefix = "blt-"
)

// BloomWithTrieIndexer implements core.ChainIndexer, building up a rotated bloom bits index
// for the YOUChain header bloom filters, permitting blazing fast filtering.
// And meanwhile building up the bloom trie for the Additional Chain of CHT.
type BloomWithTrieIndexer struct {
	size    uint64               // section size to generate bloombits for
	db      youdb.Database       // database instance to write index data and metadata into
	gen     *bloombits.Generator // generator to rotate the bloom bits crating the bloom index
	section uint64               // Section is the section number being processed currently
	head    common.Hash          // Head is the hash of the last header processed

	//trie fields
	trieTable youdb.Database
	trieDb    *trie.Database
	mnFetcher MissingNodesFetcher
	trie      *trie.Trie
}

// NewBloomIndexer returns a chain indexer that generates bloom bits data for the
// canonical chain for fast logs filtering.
func NewBloomWithTrieIndexer(db youdb.Database, fetcher MissingNodesFetcher, size, confirms uint64) *ChainIndexer {
	trieTable := youdb.NewTable(db, BloomTrieTablePrefix)
	backend := &BloomWithTrieIndexer{
		db:        db,
		size:      size,
		mnFetcher: fetcher,
		trieTable: trieTable,
		trieDb:    trie.NewDatabase(trieTable),
	}
	table := youdb.NewTable(db, string(rawdb.BloomBitsIndexPrefix))

	return NewChainIndexer(db, table, backend, size, confirms, bloomThrottling, "bloomWithTrie")
}

// Reset implements core.ChainIndexerBackend, starting a new bloombits index
// section.
func (b *BloomWithTrieIndexer) Reset(ctx context.Context, section uint64, lastSectionHead common.Hash) error {
	gen, err := bloombits.NewGenerator(uint(b.size))
	if err != nil {
		return err
	}
	//trie
	var root common.Hash
	if section > 0 {
		root = rawdb.GetBloomTrieRoot(b.db, section-1, lastSectionHead)
	}
	b.trie, err = trie.New(root, b.trieDb)
	if err != nil && b.mnFetcher != nil {
		//the trie has missing nodes, fetch them.
		err = b.mnFetcher.FetchMissingNodes(ctx, b.trie, b.trieTable, section, root)
		if err == nil {
			b.trie, err = trie.New(root, b.trieDb)
		}
	}

	b.gen, b.section, b.head = gen, section, common.Hash{}
	return err
}

// Process implements core.ChainIndexerBackend, adding a new header's bloom into
// the index.
func (b *BloomWithTrieIndexer) Process(ctx context.Context, header *types.Header) error {
	err := b.gen.AddBloom(uint(header.Number.Uint64()-b.section*b.size), header.Bloom)
	if err == nil {
		b.head = header.Hash()
	}
	return err
}

// Commit implements core.ChainIndexerBackend, finalizing the bloom section and
// writing it out into the database.
func (b *BloomWithTrieIndexer) Commit() error {
	batch := b.db.NewBatch()
	for i := 0; i < types.BloomBitLength; i++ {
		bits, err := b.gen.Bitset(uint(i))
		if err != nil {
			return err
		}
		compData, err := common.Compress(bits)
		if err != nil {
			return err
		}
		rawdb.WriteBloomBits(batch, uint(i), b.section, b.head, compData)

		//update trie
		var encKey [10]byte
		binary.BigEndian.PutUint16(encKey[0:2], uint16(i))
		binary.BigEndian.PutUint64(encKey[2:10], b.section)
		if len(compData) > 0 {
			b.trie.Update(encKey[:], compData)
		} else {
			b.trie.Delete(encKey[:])
		}
	}
	err := batch.Write()
	if err == nil {
		root, err := b.trie.Commit(nil)
		if err != nil {
			return err
		}
		err = b.trieDb.Commit(root, false)

		if err == nil {
			err = rawdb.StoreBloomTrieRoot(b.db, b.section, b.head, root)
			logging.Info("Storing bloom trie", "section", b.section, "head", fmt.Sprintf("%064x", b.head), "root", fmt.Sprintf("%064x", root), "err", err)
		}
	}
	return err
}

func (b *BloomWithTrieIndexer) TrieDB() *trie.Database {
	return b.trieDb
}
