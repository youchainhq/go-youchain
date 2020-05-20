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
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/consensus/ucon"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/p2p"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/you/downloader"
	"github.com/youchainhq/go-youchain/youdb"
	"sync"
)

type PeerEvent struct {
	peer *peer
	flag peerLifecycle
}

type UConProtocolManager struct {
	*ProtocolManager
	consensusPeersLock *sync.RWMutex
	consensusPeers     map[string]*uconPeer //id->peer
	peersFeed          event.Feed
	engine             consensus.Ucon
	eventSub           *event.TypeMuxSubscription
	quit               chan struct{}
}

type uconPeer struct {
	*peer
}

func NewUConProtocolManager(txpool txPool,
	blockchain *core.BlockChain,
	engine consensus.Ucon,
	mux *event.TypeMux,
	chainDb youdb.Database,
	mode downloader.SyncMode) (*UConProtocolManager, error) {
	// Create protocol manager
	defaultManager, err := NewProtocolManager(txpool, blockchain, engine, mux, chainDb, mode)
	if err != nil {
		return nil, err
	}

	// Create the protocol manager
	manager := &UConProtocolManager{
		ProtocolManager:    defaultManager,
		engine:             engine,
		consensusPeersLock: &sync.RWMutex{},
		consensusPeers:     make(map[string]*uconPeer),
		quit:               make(chan struct{}),
	}

	defaultManager.defaultMsgFun = manager.handleMsg
	defaultManager.peerLifecycleFun = manager.handlePeer

	return manager, nil
}

func (um *UConProtocolManager) handlePeer(p *peer, flag peerLifecycle) {
	um.consensusPeersLock.Lock()
	if flag == peerAdded {
		peer := &uconPeer{peer: p}
		um.consensusPeers[p.id] = peer
	} else {
		delete(um.consensusPeers, p.id)
	}
	um.consensusPeersLock.Unlock()

	logging.Info("um handler peer", "peer", p.String(), "flag", flag)
	um.peersFeed.Send(&PeerEvent{peer: p, flag: flag}) // send peer event to subscribers
}

func (um *UConProtocolManager) SubscribePeers(ch chan *PeerEvent) event.Subscription {
	return um.peersFeed.Subscribe(ch)
}

func (um *UConProtocolManager) Start(p2pserver interface{}, maxPeers int) {
	// Subscribe required events
	um.eventSub = um.eventMux.Subscribe(ucon.MessageEvent{}, core.ChainHeadEvent{}) //, ucon.InvalidPeerEvent{})
	go um.eventLoop()
	um.ProtocolManager.Start(p2pserver, maxPeers)

	logging.Info("ucon pm started")
}

func (um *UConProtocolManager) Stop() {
	logging.Info("Stopping protocol")
	um.engine.Stop()
	um.ProtocolManager.Stop()
	um.eventSub.Unsubscribe() // quits eventLoop
}

func (um *UConProtocolManager) GetSubProtocols() []p2p.Protocol {
	return um.ProtocolManager.GetSubProtocols()
}

func (um *UConProtocolManager) handleMsg(p *peer, msg p2p.Msg) { // mark peer
	if msg.Code == ConsensusMsg {
		data, err := rlp.NewStream(msg.Payload, uint64(msg.Size)).Bytes()
		if err != nil {
			logging.Error("handleMsg", "err", err)
			return
		}
		//um.engine.HandleMsg(data, msg.ReceivedAt, p.ID().String())
		err = um.engine.HandleMsg(data, msg.ReceivedAt) // can't use p.ID().String()
		if err != nil {
			logging.Info("InvalidPeer blacklist, and ignore putting in blacklist", "err", err, "PeerID", p.id)
			//todo if we should open this

			//um.ProtocolManager.blacklistAndRemovePeer(p.id)
		}
	} else {
		logging.Info("wrong message type:", msg.Code)
	}
}

// event loop for Caravel msg
func (um *UConProtocolManager) eventLoop() {
	for obj := range um.eventSub.Chan() {
		if obj == nil {
			continue
		}
		switch ev := obj.Data.(type) {
		case ucon.MessageEvent:
			// only for gossip msg
			um.broadcastConsensusMsg(ev)
		case core.ChainHeadEvent:
			// one new block was inserted
			um.newHead(ev)
			//case ucon.InvalidPeerEvent:
			//	// delete peer
			//	um.ProtocolManager.blacklistAndRemovePeer(ev.ID)
		}
	}
}

func (um *UConProtocolManager) broadcastConsensusMsg(ev ucon.MessageEvent) {
	um.broadcastToConsensusPeer(ev, func(peer *uconPeer) {
		peer.AsyncSendConsensus(&ev)

		//todo metrics
	})
}

func (um *UConProtocolManager) broadcastToConsensusPeer(ev ucon.MessageEvent, fn func(peer *uconPeer)) {
	um.consensusPeersLock.RLock()
	defer um.consensusPeersLock.RUnlock()
	evb, err := rlp.EncodeToBytes(ev)
	if err != nil {
		return
	}
	hash := crypto.Keccak256Hash(evb)

	var peers []uconPeer
	for _, p := range um.consensusPeers {
		if !p.knownConsensus.Contains(hash) {
			peers = append(peers, *p)
		}
	}

	for _, p := range peers {
		fn(&p)
	}
}

func (um *UConProtocolManager) Insert(block *types.Block) error {
	logging.Info("insertChain", "hash ", block.Hash().String(), "number", block.NumberU64())
	if err := um.blockchain.InsertChain(types.Blocks{block}); err != nil {
		logging.Error("Failed to insert block", "number", block.Number(), "hash", block.Hash(), "err", err)
		return err
	}
	// Only announce the block, don't broadcast it
	go um.BroadcastBlock(block, false)
	go um.BroadcastBlock(block, true)
	return nil
}

func (um *UConProtocolManager) newHead(event core.ChainHeadEvent) {
	block := event.Block
	um.engine.NewChainHead(block)
}
