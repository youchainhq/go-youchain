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

package youapi

import (
	"context"
	"errors"
	"math/big"

	"github.com/youchainhq/go-youchain/accounts"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/bloombits"
	"github.com/youchainhq/go-youchain/core/rawdb"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/node"
	"github.com/youchainhq/go-youchain/rpc"
	"github.com/youchainhq/go-youchain/you"
	"github.com/youchainhq/go-youchain/you/gasprice"
	"github.com/youchainhq/go-youchain/youdb"
)

type Container struct {
	youChain       *you.YouChain
	processor      core.Processor
	accountManager *accounts.Manager
	node           *node.Node
	Gpo            *gasprice.Oracle
}

func NewContainer(y *you.YouChain, a *accounts.Manager, n *node.Node) *Container {
	return &Container{y, y.BlockChain().Processor(), a, n, nil}
}

func (c *Container) ChainDb() youdb.Database {
	return c.youChain.ChainDb()
}

func (c *Container) TxPool() *core.TxPool {
	return c.youChain.TxPool()
}

func (c *Container) GetPoolNonce(addr common.Address) (uint64, error) {
	return c.youChain.TxPool().Nonce(addr), nil
}

func (c *Container) RPCGasCap() *big.Int {
	return c.youChain.Config().RPCGasCap
}

func (c *Container) StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	// Pending state is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		block, st := c.youChain.Miner().Pending()
		return st, block.Header(), nil
	}

	header, err := c.HeaderByNumber(ctx, blockNr)
	if err != nil {
		return nil, nil, err
	}
	if header == nil {
		return nil, nil, errors.New("header not found")
	}
	stateDb, err := c.youChain.BlockChain().StateAt(header.Root, header.ValRoot, header.StakingRoot)
	return stateDb, header, err
}

func (c *Container) GetReceipts(ctx context.Context, hash common.Hash) (types.Receipts, error) {
	return c.youChain.BlockChain().GetReceiptsByHash(hash), nil
}

func (c *Container) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	// Pending block is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		block := c.youChain.Miner().PendingBlock()
		return block.Header(), nil
	}
	bc := c.youChain.BlockChain()
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		if bc.IsLight() {
			return bc.CurrentHeader(), nil
		} else {
			return bc.CurrentBlock().Header(), nil
		}
	}
	return bc.GetHeaderByNumber(uint64(blockNr)), nil
}

func (c *Container) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	return c.youChain.BlockChain().GetHeaderByHash(hash), nil
}

func (c *Container) BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Block, error) {
	// Pending block is only known by the miner
	if blockNr == rpc.PendingBlockNumber {
		block := c.youChain.Miner().PendingBlock()
		return block, nil
	}
	// Otherwise resolve and return the block
	if blockNr == rpc.LatestBlockNumber {
		return c.youChain.BlockChain().CurrentBlock(), nil
	}
	return c.youChain.BlockChain().GetBlockByNumber(uint64(blockNr)), nil
}

func (c *Container) GetTransaction(txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	tx, blockHash, blockNumber, index := rawdb.ReadTransaction(c.youChain.ChainDb(), txHash)
	return tx, blockHash, blockNumber, index, nil
}

func (c *Container) GetPoolTransactions() (types.Transactions, error) {
	pending, err := c.youChain.TxPool().Pending()
	if err != nil {
		return nil, err
	}
	var txs types.Transactions
	for _, batch := range pending {
		txs = append(txs, batch...)
	}
	return txs, nil
}

func (c *Container) GetPoolTransaction(txHash common.Hash) *types.Transaction {
	return c.youChain.TxPool().Get(txHash)
}

func (c *Container) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return c.youChain.BlockChain().SubscribeLogsEvent(ch)
}

func (c *Container) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	return c.youChain.TxPool().SubscribeNewTxsEvent(ch)
}

func (c *Container) SubscribeRemovedLogsEvent(ch chan<- core.RemovedLogsEvent) event.Subscription {
	return c.youChain.BlockChain().SubscribeRemovedLogsEvent(ch)
}

func (c *Container) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	return c.youChain.BlockChain().SubscribeChainEvent(ch)
}

func (c *Container) GetLogs(ctx context.Context, hash common.Hash) ([][]*types.Log, error) {
	receipts := c.youChain.BlockChain().GetReceiptsByHash(hash)
	if receipts == nil {
		return nil, nil
	}
	logs := make([][]*types.Log, len(receipts))
	for i, receipt := range receipts {
		logs[i] = receipt.Logs
	}
	return logs, nil
}

func (c *Container) BloomStatus() (uint64, uint64) {
	return c.youChain.BlockChain().BloomStatus()
}

func (c *Container) ServiceFilter(ctx context.Context, session *bloombits.MatcherSession) {
	for i := 0; i < you.BloomFilterThreads; i++ {
		go session.Multiplex(you.BloomRetrievalBatch, you.BloomRetrievalWait, c.youChain.BloomRequests)
	}
}

func (c *Container) EventMux() *event.TypeMux {
	return c.youChain.EventMux()
}

func (c *Container) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	return c.youChain.TxPool().Content()
}

func (c *Container) Stats() (pending int, queued int) {
	return c.youChain.TxPool().Stats()
}

func (c *Container) ProtocolVersion() int {
	return c.youChain.YouVersion()
}

func (c *Container) SuggestPrice(ctx context.Context) (*big.Int, error) {
	return c.Gpo.SuggestPrice(ctx)
}
