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
	"github.com/youchainhq/go-youchain/core/rawdb"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/trie"
	"github.com/youchainhq/go-youchain/youdb"
	"sync"
	"time"
)

var (
	ChtTablePrefix = "cht-"
)

// ChtIndexerBackend implements core.ChainIndexerBackend.For building canonical hash trie.
type ChtIndexerBackend struct {
	diskdb, trieTable    youdb.Database //trieTable是在diskdb之上，为每个key附加一个前缀的Database接口对象
	mnFetcher            MissingNodesFetcher
	triedb               *trie.Database
	section, sectionSize uint64
	lastHash             common.Hash
	lastNum              uint64
	trie                 *trie.Trie

	lock sync.RWMutex // mutex for trie
}

// NewChtIndexer creates a Cht chain indexer
func NewChtIndexer(db youdb.Database, fetcher MissingNodesFetcher, size, confirms uint64) *ChainIndexer {
	backend := NewChtBackend(db, fetcher, size, confirms)
	return NewChainIndexer(db, youdb.NewTable(db, "chtIndex-"), backend, size, confirms, time.Millisecond*100, "cht")
}

func NewChtBackend(db youdb.Database, fetcher MissingNodesFetcher, size, confirms uint64) *ChtIndexerBackend {
	trieTable := youdb.NewTable(db, ChtTablePrefix)
	backend := &ChtIndexerBackend{
		diskdb:      db,
		trieTable:   trieTable,
		mnFetcher:   fetcher,
		triedb:      trie.NewDatabase(trieTable),
		sectionSize: size,
	}
	return backend
}

// Reset implements core.ChainIndexerBackend
func (c *ChtIndexerBackend) Reset(ctx context.Context, section uint64, lastSectionHead common.Hash) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	var root common.Hash
	if section > 0 {
		root = rawdb.GetChtRoot(c.diskdb, section-1, lastSectionHead)
	}
	var err error
	c.trie, err = trie.New(root, c.triedb)
	logging.Debug("Reset", "section", section, "sHead", lastSectionHead.String(), "root", root.String(), "err", err)

	if err != nil && c.mnFetcher != nil {
		//the trie has missing nodes, fetch them.
		err = c.mnFetcher.FetchMissingNodes(ctx, c.trie, c.trieTable, section, root)
		if err == nil {
			c.trie, err = trie.New(root, c.triedb)
		}
	}

	if err == nil {
		c.section = section
	}
	return err
}

// Process implements core.ChainIndexerBackend
func (c *ChtIndexerBackend) Process(ctx context.Context, header *types.Header) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	hash, num := header.Hash(), header.Number.Uint64()
	c.lastHash = hash
	c.lastNum = num

	var encNumber [8]byte
	binary.BigEndian.PutUint64(encNumber[:], num)
	// blockNumber:blockHash
	c.trie.Update(encNumber[:], hash.Bytes())
	//logging.Trace("cht node", "num", num, "hash", hash.String())
	return nil
}

// Commit implements core.ChainIndexerBackend
func (c *ChtIndexerBackend) Commit() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	root, err := c.trie.Commit(nil)
	if err != nil {
		return err
	}
	err = c.triedb.Commit(root, false)
	if err != nil {
		return err
	}

	err = rawdb.StoreChtRoot(c.diskdb, c.section, c.lastHash, root)
	logging.Info("Storing CHT", "section", c.section, "head", fmt.Sprintf("%064x", c.lastHash), "root", fmt.Sprintf("%064x", root), "err", err)
	return err
}

func BuildTemporaryCHT(t *trie.Trie, headers []*types.Header) common.Hash {
	for _, header := range headers {
		hash, num := header.Hash(), header.Number.Uint64()
		var encNumber [8]byte
		binary.BigEndian.PutUint64(encNumber[:], num)
		// blockNumber:blockHash
		t.Update(encNumber[:], hash.Bytes())
	}
	return t.Hash()
}

func (c *ChtIndexerBackend) GetCopiedCHT() (t *trie.Trie, headNum uint64) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.trie == nil {
		t, _ = trie.New(common.Hash{}, c.triedb)
	} else {
		cpy := *c.trie
		t = &cpy
	}
	headNum = c.lastNum
	return
}

func (c *ChtIndexerBackend) TrieDB() *trie.Database {
	return c.triedb
}

func (c *ChtIndexerBackend) GetValue(headerNum uint64) ([]byte, error) {
	var encNumber [8]byte
	binary.BigEndian.PutUint64(encNumber[:], headerNum)
	c.lock.RLock()
	defer c.lock.RUnlock()
	value, err := c.trie.TryGet(encNumber[:])
	return value, err
}
