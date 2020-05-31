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

package miner

import (
	"encoding/json"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/core/vm"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/node"
	"github.com/youchainhq/go-youchain/params"
)

const (
	// resultQueueSize is the size of channel listening to sealing result.
	resultQueueSize = 10

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096

	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10

	// staleThreshold is the maximum depth of the acceptable stale block.
	staleThreshold = 7
)

// task contains all information for consensus engine sealing and result submitting.
type task struct {
	receipts  []*types.Receipt
	state     *state.StateDB
	block     *types.Block
	createdAt time.Time
}

const (
	commitInterruptNone int32 = iota
	commitInterruptNewHead
)

type newWorkReq struct {
	interrupt *int32
}

var (
	log = logging.New()
)

type worker struct {
	nodeConfig *node.Config
	processor  core.Processor
	engine     consensus.Engine
	you        Backend
	chain      *core.BlockChain

	txsCh  chan core.NewTxsEvent
	txsSub event.Subscription

	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription

	eventMux *event.TypeMux
	eventSub *event.TypeMuxSubscription

	mu    sync.RWMutex // The lock used to protect extra fields
	extra []byte

	snapshotMu    sync.RWMutex // The lock used to protect the block snapshot and state snapshot
	snapshotBlock *types.Block
	snapshotState *state.StateDB

	newWorkCh chan newWorkReq
	taskCh    chan *task
	startCh   chan struct{}
	exitCh    chan struct{}

	current *environment

	running   int32 // The indicator whether the consensus engine is running or not.
	interrupt *int32
}

func newWorker(engine consensus.Engine, you Backend, eventMux *event.TypeMux, nodeConfig *node.Config) *worker {
	worker := &worker{
		engine:      engine,
		you:         you,
		eventMux:    eventMux,
		chain:       you.BlockChain(),
		txsCh:       make(chan core.NewTxsEvent, txChanSize),
		chainHeadCh: make(chan core.ChainHeadEvent, chainHeadChanSize),
		newWorkCh:   make(chan newWorkReq),
		taskCh:      make(chan *task),
		startCh:     make(chan struct{}, 1),
		exitCh:      make(chan struct{}),
		nodeConfig:  nodeConfig,
		processor:   you.BlockChain().Processor(),
	}
	worker.txsSub = you.TxPool().SubscribeNewTxsEvent(worker.txsCh)
	worker.chainHeadSub = you.BlockChain().SubscribeChainHeadEvent(worker.chainHeadCh)
	worker.eventSub = worker.eventMux.Subscribe(core.ChainHeadEvent{})

	go worker.update()
	go worker.newWorkLoop()
	go worker.mainLoop()
	go worker.taskLoop()

	return worker
}

func (w *worker) update() {
	for evt := range w.eventSub.Chan() {
		// A real event arrived, process interesting content
		if evt == nil {
			return
		}
		switch evt.Data.(type) {
		case core.ChainHeadEvent:
			//using channel to sync
			w.sendNewWork(commitInterruptNewHead)
		}
	}
}

func (w *worker) sendNewWork(s int32) {
	if w.interrupt != nil {
		atomic.StoreInt32(w.interrupt, s)
	}
	w.interrupt = new(int32)
	w.newWorkCh <- newWorkReq{interrupt: w.interrupt}
}

func (w *worker) mainLoop() {
	defer w.txsSub.Unsubscribe()
	defer w.chainHeadSub.Unsubscribe()

	for {
		select {
		case req := <-w.newWorkCh:
			w.commitNewWork(req.interrupt)
		case <-w.txsCh:
			//todo
		case <-w.exitCh:
			return
		}
	}
}

func (w *worker) newWorkLoop() {
	for {
		select {
		case <-w.startCh:
			w.sendNewWork(commitInterruptNewHead)
		case <-w.chainHeadCh:
		case <-w.exitCh:
			return
		}
	}
}

func (w *worker) taskLoop() {
	var (
		stopCh chan struct{}
	)

	// interrupt aborts the in-flight sealing task.
	interrupt := func() {
		if stopCh != nil {
			close(stopCh)
			stopCh = nil
		}
	}

	for {
		select {
		case task := <-w.taskCh:
			interrupt()
			stopCh = make(chan struct{})
			go w.mine(task, stopCh)
		case <-w.exitCh:
			interrupt()
			return
		}
	}
}

func (w *worker) mine(task *task, stopCh chan struct{}) {
	block, err := w.engine.Seal(w.chain, task.block, stopCh)
	if err != nil {
		return
	}
	//write to state
	if block == nil {
		return
	}

	w.postSeal(task, block)
}

func (w *worker) postSeal(task *task, block *types.Block) {
	if w.chain.HasBlock(block.Hash(), block.NumberU64()) {
		log.Warn("postSeal: exist block", "hash", block.Hash().String(), "number", block.NumberU64())
		return
	}

	// Deep copy receipts here to avoid interaction between different tasks.
	receipts := make([]*types.Receipt, len(task.receipts))
	var logs []*types.Log
	hash := block.Hash()

	for i, receipt := range task.receipts {
		receipt.BlockHash = hash
		receipt.BlockNumber = block.Number()
		receipt.TransactionIndex = uint(i)

		receipts[i] = new(types.Receipt)
		*receipts[i] = *receipt
		for _, l := range receipt.Logs {
			l.BlockHash = hash
		}
		logs = append(logs, receipt.Logs...)
	}

	bs, _ := json.Marshal(task.receipts)
	logging.Info("postseal receipts", "height", block.NumberU64(), "hash", block.Root().String(), "receiptsdata"+block.Number().String(), string(bs), "slashdata"+block.Number().String(), hexutil.Encode(block.Header().SlashData))

	w.mu.Lock()
	w.chain.WriteBlockWithState(block, task.state, receipts)
	w.mu.Unlock()

	//send mux
	chainHeadEvent := core.ChainHeadEvent{Block: block}
	go w.eventMux.Post(chainHeadEvent)

	//send to chain
	events := []interface{}{chainHeadEvent, core.NewMinedBlockEvent{Block: block}}
	events = append(events, core.ChainEvent{Block: block, Hash: block.Hash(), Logs: logs})
	w.chain.PostChainEvents(events, logs)
}

func (w *worker) commitNewWork(interrupt *int32) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	//quick fast
	if !w.isRunning() {
		log.Warn("worker is not running")
		return
	}

	//copy from engine.getValMainAddress
	coinbase := common.Address{}
	coinbase.SetBytes(w.engine.GetValMainAddress().Bytes())

	parent := w.chain.CurrentBlock()
	timestamp := uint64(time.Now().Unix())

	if timestamp <= parent.Time() {
		log.Warn("local time is far behind, use parent time plus one.")
		timestamp = parent.Time() + 1
	}

	num := parent.Number()
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     num.Add(num, common.Big1()),
		Time:       timestamp,
		Coinbase:   coinbase,
		GasLimit:   core.CalcGasLimit(parent),
		GasRewards: big.NewInt(0),
		Subsidy:    big.NewInt(0),
		Extra:      w.extra}

	// processing protocol version state
	if err := core.ProcessYouVersionState(parent.Header(), header); err != nil {
		log.Crit("fatal at ProcessYouVersionState", "err", err)
	}

	if err := w.engine.Prepare(w.chain, header); err != nil {
		log.Error("Failed to prepare header for mining", "err", err)
		return
	}

	err := w.makeCurrent(parent, header)
	if err != nil {
		log.Error("Failed to create mining context", "err", err)
		return
	}

	w.current.state.IntermediateRoot(true)

	proc := time.Now()
	txs, _ := w.you.TxPool().Pending()

	//commit txs
	txset := types.NewTransactionsByPriceAndNonce(w.current.signer, txs)

	if w.commitTransactions(txset, &coinbase, interrupt) {
		//log.Error("commitTransactions interrupt by", "id", *interrupt)
		log.Error("commitTransactions interrupt by", "id", *interrupt, "using", time.Since(proc))
		return
	}

	res, _, _ := w.processor.EndBlock(w.chain, w.current.header, w.current.txs, w.current.state, true)
	for _, receipt := range res {
		if receipt != nil {
			w.current.receipts = append(w.current.receipts, res...)
		}
	}

	err = w.commit()
	if err != nil {
		log.Error("commit", "error", err)
	}
}

func (w *worker) commitTransactions(txs *types.TransactionsByPriceAndNonce, coinbase *common.Address, interrupt *int32) bool {
	if w.current == nil {
		return true
	}

	if w.current.gasPool == nil {
		w.current.gasPool = new(core.GasPool).AddGas(w.current.header.GasLimit)
	}

	vmCfg, err := core.PrepareVMConfig(w.chain, w.current.header.Number.Uint64(), *w.chain.GetVMConfig())
	if err != nil {
		log.Error("PrepareVMConfig error", "err", err)
		return false
	}

	var coalescedLogs []*types.Log

	errorNumber := 0
	txNumber := 0
	start := time.Now()
	for {
		//interrupt the execution
		if interrupt != nil && atomic.LoadInt32(interrupt) != commitInterruptNone {
			log.Warn("interrupt at", "txnumber", txNumber, "errorNumber", errorNumber, "elapse", time.Now().Sub(start))
			return atomic.LoadInt32(interrupt) == commitInterruptNewHead
		}

		// If we don't have enough gas for any further transactions then we're done
		if w.current.gasPool.Gas() < params.TxGas {
			log.Warn("Not enough gas for further transactions", "have", w.current.gasPool, "want", params.TxGas)
			break
		}

		tx := txs.Peek()
		if tx == nil {
			break
		}
		txNumber++
		from, _ := types.Sender(w.current.signer, tx)

		w.current.state.Prepare(tx.Hash(), common.Hash{}, w.current.tcount)
		logs, err := w.commitTransaction(vmCfg, tx, coinbase)
		if err != nil {
			log.Error("commitTransaction", "err", err)
			errorNumber++
		}
		switch err {
		case core.ErrGasLimitReached:
			// Pop the current out-of-gas transaction without shifting in the next from the account
			log.Trace("Gas limit exceeded for current block", "sender", from)
			txs.Pop()
		case core.ErrNonceTooLow:
			txs.Shift()
		case core.ErrNonceTooHigh:
			txs.Pop()
		case nil:
			coalescedLogs = append(coalescedLogs, logs...)
			w.current.tcount++
			txs.Shift()
		default:
			log.Debug("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			txs.Shift()
		}
	}
	log.Warn("commit go through", "txnumber", txNumber, "elapse", time.Now().Sub(start))

	return false
}

func (w *worker) commitTransaction(vmCfg *vm.Config, tx *types.Transaction, coinbase *common.Address) ([]*types.Log, error) {
	snap := w.current.state.Snapshot()
	receipt, _, err := w.processor.ApplyTransaction(tx, w.current.signer, w.current.state, w.chain, w.current.header, coinbase, &w.current.header.GasUsed, w.current.header.GasRewards, w.current.gasPool, vmCfg)
	if err != nil {
		log.Error("commitTransaction: apply transition failed", "err", err, "number", w.current.header.Number, "tx", tx.Hash().String())
		w.current.state.RevertToSnapshot(snap)
		return nil, err
	}
	w.current.txs = append(w.current.txs, tx)
	w.current.receipts = append(w.current.receipts, receipt)
	return receipt.Logs, nil
}

func (w *worker) commit() error {
	// Deep copy receipts here to avoid interaction between different tasks.
	receipts := make([]*types.Receipt, len(w.current.receipts))
	for i, l := range w.current.receipts {
		receipts[i] = new(types.Receipt)
		*receipts[i] = *l
	}

	s := w.current.state
	block, err := w.engine.FinalizeAndAssemble(w.chain, w.current.header, s, w.current.txs, w.current.receipts)
	if err != nil {
		return err
	}
	bs, _ := json.Marshal(w.current.receipts)
	rbloom := types.CreateBloom(receipts)
	logging.Trace("commit block", "height", block.NumberU64(), "hash", block.Hash().String(), "receiptsData"+block.Number().String(), string(bs), "bloom", hexutil.Encode(rbloom.Bytes()), "slashdata"+block.Number().String(), hexutil.Encode(block.Header().SlashData))
	//only running
	if w.isRunning() {
		select {
		case w.taskCh <- &task{receipts: receipts, state: s, block: block, createdAt: time.Now()}:
		case <-w.exitCh:
			log.Warn("commit: worker has existed")
		}
	}

	w.updateSnapshot()
	return nil
}

func (w *worker) makeCurrent(parent *types.Block, header *types.Header) error {
	yp, err := w.chain.VersionForRound(header.Number.Uint64())
	if err != nil {
		return err
	}
	stakingRoot := core.StakingRootForNewBlock(yp.StakingTrieFrequency, parent.Header())
	statedb, err := w.chain.StateAt(parent.Root(), parent.ValRoot(), stakingRoot)
	if err != nil {
		return err
	}

	env := &environment{
		signer: types.MakeSigner(header.Number),
		state:  statedb,
		header: header}

	env.tcount = 0
	w.current = env

	return nil
}

// environment is the worker's current environment and holds all of the current state information.
type environment struct {
	signer types.Signer

	state   *state.StateDB // apply state changes here
	gasPool *core.GasPool  // available gas used to pack transactions
	tcount  int            // tx count in cycle

	header   *types.Header
	txs      []*types.Transaction
	receipts []*types.Receipt
}

func (w *worker) stop() {
	atomic.StoreInt32(&w.running, 0)
}
func (w *worker) start() {
	atomic.StoreInt32(&w.running, 1)
	w.startCh <- struct{}{}
}

func (w *worker) isRunning() bool {
	return atomic.LoadInt32(&w.running) == 1
}

// close terminates all background threads maintained by the worker.
// Note the worker does not support being closed multiple times.
func (w *worker) close() {
	close(w.exitCh)
}

// updateSnapshot updates pending snapshot block and state. 暂存快照
func (w *worker) updateSnapshot() {
	w.snapshotMu.Lock()
	defer w.snapshotMu.Unlock()

	w.snapshotBlock = types.NewBlock(
		w.current.header,
		w.current.txs,
		w.current.receipts,
	)

	w.snapshotState = w.current.state.Copy()
}

// pending returns the pending state and corresponding block.
func (w *worker) pending() (*types.Block, *state.StateDB) {
	// return a snapshot to avoid contention on currentMu mutex
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	if w.snapshotState == nil {
		return nil, nil
	}
	return w.snapshotBlock, w.snapshotState.Copy()
}

// pendingBlock returns pending block.
func (w *worker) pendingBlock() *types.Block {
	// return a snapshot to avoid contention on currentMu mutex
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	return w.snapshotBlock
}

// setExtra sets the content used to initialize the block extra field.
func (w *worker) setExtra(extra []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.extra = extra
}
