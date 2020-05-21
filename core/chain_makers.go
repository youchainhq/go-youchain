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

package core

import (
	"fmt"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/core/rawdb"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/core/vm"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/youdb"
	"math/big"
)

type BlockGen struct {
	i       int
	parent  *types.Block
	chain   []*types.Block
	header  *types.Header
	statedb *state.StateDB

	processor Processor

	gasPool  *GasPool
	txs      []*types.Transaction
	receipts []*types.Receipt

	engine consensus.Engine
}

func (b *BlockGen) Receipts() []*types.Receipt {
	return b.receipts
}

func (b *BlockGen) Statedb() *state.StateDB {
	return b.statedb
}

func (b *BlockGen) Header() *types.Header {
	return b.header
}

// SetCoinbase sets the coinbase of the generated block.
// It can be called at most once.
func (b *BlockGen) SetCoinbase(addr common.Address) {
	if b.gasPool != nil {
		if len(b.txs) > 0 {
			panic("coinbase must be set before adding transactions")
		}
		panic("coinbase can only be set once")
	}
	b.header.Coinbase = addr
	b.gasPool = new(GasPool).AddGas(b.header.GasLimit)
}

// SetExtra sets the extra data field of the generated block.
func (b *BlockGen) SetExtra(data []byte) {
	b.header.Extra = data
}

// AddTx adds a transaction to the generated block. If no coinbase has
// been set, the block's coinbase is set to the zero address.
//
// AddTx panics if the transaction cannot be executed. In addition to
// the protocol-imposed limitations (gas limit, etc.), there are some
// further limitations on the content of transactions that can be
// added. Notably, contract code relying on the BLOCKHASH instruction
// will panic during execution.
func (b *BlockGen) AddTx(tx *types.Transaction) {
	b.AddTxWithChain(&fakeChainReader{}, tx)
}

func (b *BlockGen) AddTxWithChain(bc ChainContext, tx *types.Transaction) {
	if b.gasPool == nil {
		b.SetCoinbase(common.Address{})
	}
	b.statedb.Prepare(tx.Hash(), common.Hash{}, len(b.txs))
	vmCfg, err := PrepareVMConfig(bc, b.header.Number.Uint64(), vm.LocalConfig{})
	if err != nil {
		panic(err)
	}
	receipt, _, err := b.processor.ApplyTransaction(tx, types.MakeSigner(b.header.Number), b.statedb, bc, b.header, &b.header.Coinbase, &b.header.GasUsed, b.header.GasRewards, b.gasPool, vmCfg)
	if err != nil {
		panic(err)
	}
	b.txs = append(b.txs, tx)
	b.receipts = append(b.receipts, receipt)
}

// Number returns the block number of the block being generated.
func (b *BlockGen) Number() *big.Int {
	return new(big.Int).Set(b.header.Number)
}

// TxNonce returns the next valid transaction nonce for the
// account at addr. It panics if the account does not exist.
func (b *BlockGen) TxNonce(addr common.Address) uint64 {
	if !b.statedb.Exist(addr) {
		panic("account does not exist")
	}
	return b.statedb.GetNonce(addr)
}

// PrevBlock returns a previously generated block by number. It panics if
// num is greater or equal to the number of the block being generated.
// For index -1, PrevBlock returns the parent block given to GenerateChain.
func (b *BlockGen) PrevBlock(index int) *types.Block {
	if index >= b.i {
		panic(fmt.Errorf("block index %d out of range (%d,%d)", index, -1, b.i))
	}
	if index == -1 {
		return b.parent
	}
	return b.chain[index]
}

// OffsetTime modifies the time instance of a block, implicitly changing its
// associated difficulty. It's useful to test scenarios where forking is not
// tied to chain length directly.
func (b *BlockGen) OffsetTime(seconds int64) {
	b.header.Time += uint64(seconds)
	if b.header.Time <= b.parent.Header().Time {
		panic("block time out of range")
	}
}

func GenerateChain(parent *types.Block, engine consensus.Engine, db youdb.Database, n int, processor Processor, gen func(int, *BlockGen)) ([]*types.Block, []types.Receipts) {
	return generateChain(parent, engine, db, n, processor, gen)
}

// GenerateChain creates a chain of n blocks. The first block's
// parent will be the provided parent. db is used to store
// intermediate states and should contain the parent's state trie.
//
// The generator function is called with a new block generator for
// every block. Any transactions and uncles added to the generator
// become part of the block. If gen is nil, the blocks will be empty
// and their coinbase will be the zero address.
//
// Blocks created by GenerateChain do not contain valid proof of work
// values. Inserting them into BlockChain requires use of FakePow or
// a similar non-validating proof of work implementation.
func generateChain(parent *types.Block, engine consensus.Engine, db youdb.Database, n int, processor Processor, gen func(int, *BlockGen)) ([]*types.Block, []types.Receipts) {
	blocks, receipts := make(types.Blocks, n), make([]types.Receipts, n)
	chainreader := &fakeChainReader{}
	genblock := func(i int, parent *types.Block, statedb *state.StateDB) (*types.Block, types.Receipts) {
		b := &BlockGen{i: i, chain: blocks, parent: parent, statedb: statedb, engine: engine, processor: processor}
		b.header = makeHeader(chainreader, parent, statedb, b.engine)
		logging.Info("makeHeader", "parent", b.parent.Number(), "hash", b.parent.Hash().String(), "root", b.parent.Root().String(), "parentHash", b.parent.ParentHash().String())

		// Execute any user modifications to the block
		if gen != nil {
			gen(i, b)
		}
		if b.engine != nil {
			if b.processor != nil {
				receipts, _, _ := b.processor.EndBlock(chainreader, b.header, b.txs, statedb, true)
				for _, receipt := range receipts {
					if receipt != nil {
						b.receipts = append(b.receipts, receipt)
					}
				}
			}
			// Finalize and seal the block
			block, _ := b.engine.FinalizeAndAssemble(chainreader, b.header, statedb, b.txs, b.receipts)
			// Write state changes to db
			root, valRoot, stakingRoot, err := statedb.Commit(true)
			if err != nil {
				panic(fmt.Sprintf("state write error: %v", err))
			}
			for key, value := range map[string]common.Hash{"state": root, "val": valRoot, "staking": stakingRoot} {
				if err := statedb.Database().TrieDB().Commit(value, false); err != nil {
					panic(fmt.Sprintf("%s trie write error: %v", key, err))
				}
			}

			return block, b.receipts
		}
		return nil, nil
	}

	for i := 0; i < n; i++ {
		// don't mind staking root here, cause currently can't use a caravel engine for generateChain
		statedb, err := state.New(parent.Root(), parent.ValRoot(), parent.StakingRoot(), state.NewDatabase(db))
		if err != nil {
			panic(err)
		}
		block, receipt := genblock(i, parent, statedb)
		blocks[i] = block
		receipts[i] = receipt
		parent = block
	}
	return blocks, receipts
}

func makeHeader(chain consensus.ChainReader, parent *types.Block, state *state.StateDB, engine consensus.Engine) *types.Header {
	var time uint64
	if parent.Time() == 0 {
		time = uint64(10)
	} else {
		time = parent.Time() + uint64(10) // block time is fixed at 10 seconds
	}

	root, valRoot, stakingRoot := state.IntermediateRoot(true)
	return &types.Header{
		Root:        root,
		ValRoot:     valRoot,
		StakingRoot: stakingRoot,
		ParentHash:  parent.Hash(),
		Coinbase:    parent.Coinbase(),
		GasRewards:  big.NewInt(0),
		Subsidy:     big.NewInt(0),
		GasLimit:    CalcGasLimit(parent),
		Number:      new(big.Int).Add(parent.Number(), common.Big1()),
		Time:        time,
		//make sure there's no nil fields
		Extra:       []byte{},
		SlashData:   []byte{},
		Consensus:   []byte{},
		ChtRoot:     []byte{},
		BltRoot:     []byte{},
		Signature:   []byte{},
		Validator:   []byte{},
		Certificate: []byte{},
		CurrVersion: params.YouCurrentVersion,
	}
}

// makeHeaderChain creates a deterministic chain of headers rooted at parent.
func makeHeaderChain(parent *types.Header, n int, engine consensus.Engine, db youdb.Database, seed int) []*types.Header {
	blocks := makeBlockChain(types.NewBlockWithHeader(parent), n, engine, db, seed)
	headers := make([]*types.Header, len(blocks))
	for i, block := range blocks {
		headers[i] = block.Header()
	}
	return headers
}

// makeBlockChain creates a deterministic chain of blocks rooted at parent.
func makeBlockChain(parent *types.Block, n int, engine consensus.Engine, db youdb.Database, seed int) []*types.Block {
	processor := NewStateProcessor(nil, engine)
	blocks, _ := GenerateChain(parent, engine, db, n, processor, func(i int, b *BlockGen) {
		b.SetCoinbase(common.Address{0: byte(seed), 19: byte(i)})
	})
	return blocks
}

type fakeChainReader struct {
	genesis *types.Block
}

func (cr *fakeChainReader) CurrentHeader() *types.Header                            { return nil }
func (cr *fakeChainReader) GetHeaderByNumber(number uint64) *types.Header           { return nil }
func (cr *fakeChainReader) GetHeaderByHash(hash common.Hash) *types.Header          { return nil }
func (cr *fakeChainReader) GetHeader(hash common.Hash, number uint64) *types.Header { return nil }
func (cr *fakeChainReader) GetBlock(hash common.Hash, number uint64) *types.Block   { return nil }
func (cr *fakeChainReader) GetBlockByNumber(number uint64) *types.Block             { return nil }
func (cr *fakeChainReader) GetVldReader(valRoot common.Hash) (state.ValidatorReader, error) {
	return nil, nil
}
func (cr *fakeChainReader) HasBlockAndState(hash common.Hash, number uint64) bool { return false }
func (cr *fakeChainReader) GetAcReader() rawdb.AcReader                           { return nil }
func (cr *fakeChainReader) UpdateExistedHeader(header *types.Header)              {}

func (cr *fakeChainReader) VersionForRound(r uint64) (*params.YouParams, error) {
	yp := params.Versions[params.YouCurrentVersion]
	return &yp, nil
}
func (cr *fakeChainReader) VersionForRoundWithParents(r uint64, parents []*types.Header) (*params.YouParams, error) {
	yp := params.Versions[params.YouCurrentVersion]
	return &yp, nil
}
