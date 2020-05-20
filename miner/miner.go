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
	"fmt"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/node"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/you/downloader"
	"sync/atomic"
)

type Backend interface {
	BlockChain() *core.BlockChain
	TxPool() *core.TxPool
}

type NewMinedBlockSubscriber interface {
	SubscribeNewMinedBlockEvent(chan core.NewMinedBlockEvent) event.Subscription
}

type Miner struct {
	mux    *event.TypeMux
	engine consensus.Engine

	worker *worker

	quit chan bool // quit channel

	canStart    int32 // can start indicates whether we can start the mining operation
	shouldStart int32 // should start indicates whether we should start after sync
}

func NewMiner(you Backend, mux *event.TypeMux, engine consensus.Engine, nodeConfig *node.Config) *Miner {
	miner := &Miner{
		mux:      mux,
		engine:   engine,
		worker:   newWorker(engine, you, mux, nodeConfig),
		quit:     make(chan bool),
		canStart: 1}

	go miner.update()

	return miner
}

func (m *Miner) update() {
	events := m.mux.Subscribe(downloader.StartEvent{}, downloader.DoneEvent{}, downloader.FailedEvent{})
	defer events.Unsubscribe()

	for {
		select {
		case ev := <-events.Chan():
			if ev == nil {
				return
			}
			switch ev.Data.(type) {
			case downloader.StartEvent:
				log.Info("miner recv StartEvent")
				atomic.StoreInt32(&m.canStart, 0)
				if m.worker.isRunning() {
					m.Stop()
					atomic.StoreInt32(&m.shouldStart, 1)
					log.Info("mining aborted due to sync")
				}
			case downloader.DoneEvent, downloader.FailedEvent:
				shouldStart := atomic.LoadInt32(&m.shouldStart) == 1

				log.Info("miner recv DoneEvent,FailedEvent")
				atomic.StoreInt32(&m.canStart, 1)
				atomic.StoreInt32(&m.shouldStart, 0)
				if shouldStart {
					m.Start()
				}
				// stop immediately and ignore all further pending events
				return
			}
		case <-m.quit:
			return
		}
	}
}

func (m *Miner) Start() {
	atomic.StoreInt32(&m.shouldStart, 1)
	if atomic.LoadInt32(&m.canStart) == 0 {
		log.Info("Network syncing, will start miner afterwards")
		return
	}
	m.worker.start()
}

func (m *Miner) Stop() {
	m.worker.stop()
	atomic.StoreInt32(&m.shouldStart, 0)
}

func (m *Miner) Close() {
	m.worker.close()
	close(m.quit)
}

func (m *Miner) Mining() bool {
	return m.worker.isRunning()
}

// Pending returns the currently pending block and associated state.
func (m *Miner) Pending() (*types.Block, *state.StateDB) {
	return m.worker.pending()
}

func (m *Miner) PendingBlock() *types.Block {
	return m.worker.pendingBlock()
}

func (m *Miner) SetExtra(extra []byte) error {
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra exceeds max length. %d > %v", len(extra), params.MaximumExtraDataSize)
	}
	m.worker.setExtra(extra)
	return nil
}
