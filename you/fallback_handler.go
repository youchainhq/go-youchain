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

package you

import (
	"encoding/json"
	"fmt"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/p2p"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/rpc"
	"github.com/youchainhq/go-youchain/you/downloader"
	"io/ioutil"
	"net/url"

	"github.com/hashicorp/golang-lru"
)

const (
	txCacheSize    = 1000
	blockCacheSize = 100
)

type FallbackHandlerConfig struct {
	Urls       []string `json:"urls"`
	CurrentIdx int      `json:"current_idx"`
}

type RemoteNode struct {
	client *rpc.Client
	url    string
}

type FallbackHandler struct {
	config     FallbackHandlerConfig
	nodes      []RemoteNode
	currentIdx int

	txCache    *lru.Cache
	blockCache *lru.Cache

	txsCh  chan core.NewTxsEvent
	txsSub event.Subscription

	newMinedBlockCh  chan core.NewMinedBlockEvent
	newMinedBlockSub event.Subscription

	txPool     *core.TxPool
	blockChain *core.BlockChain
}

func NewFallbackHandler(configPath string, txPool *core.TxPool, bc *core.BlockChain) *FallbackHandler {
	if configPath == "" {
		logging.Crit("empty config")
	}

	config := FallbackHandlerConfig{}
	bs, err := ioutil.ReadFile(configPath)
	err = json.Unmarshal(bs, &config)
	if err != nil {
		logging.Crit(err.Error())
	}

	if config.CurrentIdx < 0 || config.CurrentIdx > len(config.Urls)-1 {
		logging.Crit("error index or nodes", config)
	}

	logging.Info("fallback:", config)

	nodes := make([]RemoteNode, len(config.Urls))
	for i, urlRaw := range config.Urls {
		_, err := url.Parse(urlRaw)
		if err != nil {
			logging.Error("parse", "err", err)
			continue
		}
		if i != config.CurrentIdx {
			client, err := rpc.Dial(urlRaw)
			if err != nil {
				logging.Error("error dialing:", urlRaw)
			} else {
				nodes[i] = RemoteNode{client, urlRaw}
			}
		}
	}

	txCache, _ := lru.New(txCacheSize)
	blockCache, _ := lru.New(blockCacheSize)
	return &FallbackHandler{
		config:          config,
		txCache:         txCache,
		blockCache:      blockCache,
		nodes:           nodes,
		currentIdx:      config.CurrentIdx,
		txPool:          txPool,
		blockChain:      bc,
		txsCh:           make(chan core.NewTxsEvent),
		newMinedBlockCh: make(chan core.NewMinedBlockEvent)}
}

func (handler *FallbackHandler) Start(p2pserver interface{}, maxPeers int) {
	handler.txsCh = make(chan core.NewTxsEvent, txChanSize)
	handler.txsSub = handler.txPool.SubscribeNewTxsEvent(handler.txsCh)

	// broadcast mined blocks
	handler.newMinedBlockCh = make(chan core.NewMinedBlockEvent, blockChanSize)
	handler.newMinedBlockSub = handler.blockChain.SubscribeNewMinedBlockEvent(handler.newMinedBlockCh)

	go handler.txsLoop()

	go handler.blockLoop()
}

func (handler *FallbackHandler) Downloader() *downloader.Downloader {
	return nil
}

func (handler *FallbackHandler) Config() FallbackHandlerConfig {
	return handler.config
}

func (handler *FallbackHandler) GetSubProtocols() []p2p.Protocol {
	return nil
}

func (handler *FallbackHandler) AddPeerByAddr(addr string) {

}

func (handler *FallbackHandler) txsLoop() {
	for {
		select {
		case evt := <-handler.txsCh:
			handler.onTxs(evt.Txs)
		}
	}
}

func (handler *FallbackHandler) blockLoop() {
	for {
		select {
		case evt := <-handler.newMinedBlockCh:
			handler.onBlock(evt.Block)
		}
	}
}

func (handler *FallbackHandler) onTxs(txs types.Transactions) {
	var txsSend types.Transactions
	for _, tx := range txs {
		if _, ok := handler.txCache.Get(tx.Hash()); !ok {
			handler.txCache.Add(tx.Hash(), tx)
			txsSend = append(txsSend, tx)
		} else {
			logging.Info("tx stop propagation", tx.Hash().String(), tx.Nonce())
		}
	}

	//stop propagation
	if len(txsSend) == 0 {
		return
	}

	for i, node := range handler.nodes {
		if handler.currentIdx != i {
			logging.Info("sendTxs", node.url)
			node.sendTxs(txsSend)
		}
	}
}

func (handler *FallbackHandler) onBlock(block *types.Block) {
	if _, ok := handler.blockCache.Get(block.Hash()); ok {
		logging.Info("block stop propagation", block.Hash().String(), block.NumberU64())
		return
	}

	//stop propagation
	handler.blockCache.Add(block.Hash(), block)

	for i, node := range handler.nodes {
		if handler.currentIdx != i {
			logging.Info("sendBlock", node.url)
			node.sendBlock(block)
		}
	}
}

func (handler *FallbackHandler) Stop() {
	handler.txsSub.Unsubscribe()
	handler.newMinedBlockSub.Unsubscribe()
}

func (handler *FallbackHandler) Insert(block *types.Block) error {
	return nil
}

func (node *RemoteNode) sendTxs(txs types.Transactions) error {
	rlpTxs, err := rlp.EncodeToBytes(txs)
	if err != nil {
		return nil
	}
	var a interface{}
	if err := node.client.Call(&a, "miner_addTxs", rlpTxs); err != nil {
		fmt.Println(err.Error())
		return err
	}
	return nil
}

func (node *RemoteNode) sendBlock(block *types.Block) error {
	rlpBlock, err := rlp.EncodeToBytes(block)
	if err != nil {
		return nil
	}
	var a interface{}
	if err := node.client.Call(&a, "miner_addBlock", rlpBlock); err != nil {
		fmt.Println(err.Error())
		return err
	}
	return nil
}
