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

package consensus

import (
	"crypto/ecdsa"
	"math/big"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/rawdb"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/params"
)

type ChainReader interface {
	// VersionForRound retrieves the YOUChain protocol parameters for the specific round
	VersionForRound(round uint64) (*params.YouParams, error)
	// VersionForRoundWithParents is the same as VersionForRound,
	// except that it will first try get the params-round header from block-chain,
	// if failed and the `parents` is not nil,
	// then it will try finding the header from `parents`.
	// It's the caller's responsibility to make sure that the parents are trusted.
	VersionForRoundWithParents(round uint64, parents []*types.Header) (*params.YouParams, error)

	// CurrentHeader retrieves the current header from the local chain.
	CurrentHeader() *types.Header

	// GetHeader retrieves a block header from the database by hash and number.
	GetHeader(hash common.Hash, number uint64) *types.Header

	// GetHeaderByNumber retrieves a block header from the database by number.
	GetHeaderByNumber(number uint64) *types.Header

	// GetHeaderByHash retrieves a block header from the database by its hash.
	GetHeaderByHash(hash common.Hash) *types.Header

	// GetBlock retrieves a block from the database by hash and number.
	GetBlock(hash common.Hash, number uint64) *types.Block

	// GetBlock retrieves a block from the canonical chain by number.
	GetBlockByNumber(number uint64) *types.Block

	// GetVldReader returns a new validator reader based on the specific valRoot.
	GetVldReader(valRoot common.Hash) (state.ValidatorReader, error)

	// GetAcReader returns an AcReader for reading ac node from database
	GetAcReader() rawdb.AcReader

	// UpdateExistedHeader updates the votes' info of the existed block header,
	// without changing the header's number and hash
	UpdateExistedHeader(header *types.Header)
}

type MineInserter interface {
	//Insert is used by a miner to handle a new mined block before serializing to local chain
	Insert(block *types.Block) error
}
type Engine interface {
	Author(header *types.Header) (common.Address, error)

	// VerifyHeader checks whether a header conforms to the consensus rules of a
	// given engine. Verifying the seal may be done optionally here, or explicitly
	// via the VerifySeal method.
	VerifyHeader(chain ChainReader, header *types.Header, seal bool) error

	// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
	// concurrently. The method returns a quit channel to abort the operations and
	// a results channel to retrieve the async verifications (the order is that of
	// the input slice).
	VerifyHeaders(chain ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error)

	// VerifySeal checks whether the crypto seal on a header is valid according to
	// the consensus rules of the given engine.
	VerifySeal(chain ChainReader, header *types.Header) error

	UpdateContextForNewBlock(block *types.Block) error

	Prepare(chain ChainReader, header *types.Header) error

	// Finalize runs any post-transaction state modifications (e.g. block rewards)
	// but does not assemble the block.
	//
	// Note: The block header is for read only, but the state database might be updated to reflect any
	// consensus rules that happen at finalization (e.g. block rewards).
	// This method should be used only for replaying a mined-block's transactions.
	Finalize(chain ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt)

	// FinalizeAndAssemble runs any post-transaction state modifications (e.g. block
	// rewards) and assembles the final block.
	//
	// Note: The block header and state database might be updated to reflect any
	// consensus rules that happen at finalization (e.g. block rewards).
	FinalizeAndAssemble(chain ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
		receipts []*types.Receipt) (*types.Block, error)

	// Seal generates a new block for the given input block with the local miner's
	// seal place on top.
	Seal(chain ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error)

	CompareBlocks(blockA *types.Block, blockB *types.Block) int

	//SetValKey sets the validator key
	SetValKey(sk *ecdsa.PrivateKey, blsKeyBytes []byte) (err error)

	//return main address for coinbase
	GetValMainAddress() common.Address

	//StartMining starts the engine for mining
	StartMining(chain ChainReader, inserter MineInserter, eventMux *event.TypeMux) error

	// Stop the engine
	Stop() error
}

type Ucon interface {
	Engine

	// Handle a message from peer
	HandleMsg(data []byte, receivedAt time.Time) error

	// Receive new chain head block
	NewChainHead(block *types.Block)

	// return the stake-look-back block number for the specific block number.
	// If the cp is nil, then it will try get CaravelParams according to num.
	GetLookBackBlockNumber(cp *params.CaravelParams, num *big.Int, lbType params.LookBackType) *big.Int

	// checks whether a side chain block confirms to the consensus rules
	VerifySideChainHeader(cp *params.CaravelParams, seedHeader *types.Header, vldReader state.ValidatorReader, certHeader *types.Header, certVldReader state.ValidatorReader, block *types.Block, parents []*types.Block) error

	// VerifyAcHeader verifies the header using and only using cht certificates
	VerifyAcHeader(chain ChainReader, acHeader *types.Header, verifiedAcParents []*types.Header) error
}
