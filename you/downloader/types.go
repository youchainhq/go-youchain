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

package downloader

import (
	"fmt"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
)

// peerDropFn is a callback type for dropping a peer detected as malicious.
type peerDropFn func(id string)

// dataPack is a data message returned by a peer for some query.
type dataPack interface {
	PeerId() string
	Items() int
	Stats() string
}

// headerPack is a batch of block headers returned by a peer.
type blocksPack struct {
	peerID string
	blocks types.Blocks
}

func (p *blocksPack) PeerId() string { return p.peerID }
func (p *blocksPack) Items() int     { return len(p.blocks) }
func (p *blocksPack) Stats() string  { return fmt.Sprintf("%d", len(p.blocks)) }

// triePack is a batch of trie nodes returned by a peer.
type triePack struct {
	peerID string
	nodes  [][]byte
}

func (p *triePack) PeerId() string { return p.peerID }
func (p *triePack) Items() int     { return len(p.nodes) }
func (p *triePack) Stats() string  { return fmt.Sprintf("%d", len(p.nodes)) }

// headerPack is a batch of block headers returned by a peer.
type headerPack struct {
	peerID  string
	headers []*types.Header
}

func (p *headerPack) PeerId() string { return p.peerID }
func (p *headerPack) Items() int     { return len(p.headers) }
func (p *headerPack) Stats() string  { return fmt.Sprintf("%d", len(p.headers)) }

type bodyPack struct {
	peerID       string
	transactions [][]*types.Transaction
}

func (p *bodyPack) PeerId() string { return p.peerID }
func (p *bodyPack) Items() int     { return len(p.transactions) }
func (p *bodyPack) Stats() string  { return fmt.Sprintf("%d", len(p.transactions)) }

// receiptPack is a batch of receipts returned by a peer.
type receiptPack struct {
	peerID   string
	receipts [][]*types.Receipt
}

func (p *receiptPack) PeerId() string { return p.peerID }
func (p *receiptPack) Items() int     { return len(p.receipts) }
func (p *receiptPack) Stats() string  { return fmt.Sprintf("%d", len(p.receipts)) }

type blockHashPack struct {
	peerID string
	Hash   common.Hash // Block hash from which to retrieve headers (excludes Number)
	Number uint64      // Block hash from which to retrieve headers (excludes Hash)
}

func (p *blockHashPack) PeerId() string { return p.peerID }
func (p *blockHashPack) Items() int     { return 0 }
func (p *blockHashPack) Stats() string  { return fmt.Sprintf("%d", p.Number) }

type SyncProgress struct {
	StartingBlock uint64 // Block number where sync began
	CurrentBlock  uint64 // Current block number where sync is at
	HighestBlock  uint64 // Highest alleged block number in the chain
	PulledStates  uint64 // Number of state trie entries already downloaded
	KnownStates   uint64 // Total number of state trie entries known about
}
