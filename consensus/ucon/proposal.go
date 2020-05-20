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

package ucon

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
)

type StartVoteFn func(round *big.Int, roundIndex uint32) bool

type Proposal struct {
	lock        sync.Mutex
	round       *big.Int
	roundIndex  uint32
	step        uint32
	priorityMgr *PriorityManager

	verifyFn    VerifyPriorityFn
	startVoteFn StartVoteFn

	eventMux *event.TypeMux // send notifications
	eventSub *event.TypeMuxSubscription
}

func NewProposal(eventMux *event.TypeMux, verifyFn VerifyPriorityFn, startVoteFn StartVoteFn) *Proposal {
	p := &Proposal{
		eventMux:    eventMux,
		priorityMgr: NewPriorityMgr(),
		verifyFn:    verifyFn,
		startVoteFn: startVoteFn,
	}

	return p
}

func (p *Proposal) Start() {
	p.eventSub = p.eventMux.Subscribe(BlockProposalEvent{}, ContextChangeEvent{}, PriorityMsgEvent{}, ProposedBlockMsgEvent{}) //, RoundIndexChangeEvent{})

	go p.eventLoop()
}

func (p *Proposal) Stop() {
	p.eventSub.Unsubscribe()
}

func (p *Proposal) eventLoop() {
	for obj := range p.eventSub.Chan() {
		if obj == nil {
			return
		}
		switch ev := obj.Data.(type) {
		case BlockProposalEvent:
			p.newProposedBlock(ev.Block)
		case ContextChangeEvent:
			p.updateContext(ev)
		case PriorityMsgEvent:
			p.processPriorityMessage(ev.Msg, msgSame) //, ev.FromCache)
		case ProposedBlockMsgEvent:
			p.processProposedBlockMsg(ev.Msg, msgSame) //, ev.FromCache)
		}
	}
}

func (p *Proposal) newProposedBlock(block *types.Block) {
	if block == nil {
		return
	}
	consensus, err := GetConsensusDataFromHeader(block.Header())
	if err != nil {
		return
	}

	// check whether should gossip the proposed block.
	if !p.priorityMgr.isMaxPriority(consensus.Priority, consensus.Round, consensus.RoundIndex) {
		return
	}

	// check the status of vote. If there is a hash which has enough votes, do not gossip
	if p.startVoteFn(consensus.Round, consensus.RoundIndex) {
		logging.Info("Already StartVote.", "Round", consensus.Round, "RoundIndex", consensus.RoundIndex)
		return
	}

	// gossip the proposed priority and block
	err = p.gossipProposal(block, consensus)
	if err != nil {
		return
	}

	// cache the new proposed block
	p.priorityMgr.update(block, block.Hash(), consensus.Priority, consensus.Round, consensus.RoundIndex)
}

func (p *Proposal) updateContext(ev ContextChangeEvent) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if ev.Round == nil {
		return
	}
	if p.round == nil || p.round.Cmp(ev.Round) != 0 {
		p.round = ev.Round
		p.priorityMgr.clearData(ev.Round)
	}
	p.roundIndex = ev.RoundIndex
	p.step = ev.Step
}

func (p *Proposal) gossipProposal(block *types.Block, consensus *BlockConsensusData) error {
	//  gossip the priority
	err := p.gossipPriority(block, consensus)
	if err != nil {
		return err
	}

	// gossip the block
	err = p.gossipBlock(block, consensus)
	if err != nil {
		return err
	}

	return nil
}

func (p *Proposal) gossipPriority(block *types.Block, consensus *BlockConsensusData) error {
	priorityMsg := ConsensusCommon{
		Round:          consensus.Round,
		RoundIndex:     consensus.RoundIndex,
		Step:           UConStepProposal,
		Priority:       consensus.Priority,
		SortitionProof: consensus.SortitionProof,
		SubUsers:       consensus.SubUsers,
		BlockHash:      block.Hash(),
		ParentHash:     block.ParentHash(),
		Timestamp:      uint64(time.Now().Unix()),
	}

	ecp, err := Encode(priorityMsg)
	if err != nil {
		logging.Error("Encode priority message failed.", err)
		return fmt.Errorf("encode priority message failed: %x,%x", priorityMsg, err)
	}

	// gossip priority messages
	p.eventMux.AsyncPost(SendMessageEvent{Code: msgPriorityProposal, Payload: ecp, Round: consensus.Round})
	//logging.Info("send msgPriorityProposal.", "Round", consensus.Round, "RoundIndex", consensus.RoundIndex, "hash", block.Hash().String())

	return nil
}

func (p *Proposal) gossipBlock(block *types.Block, consensus *BlockConsensusData) error {
	ecp, err := Encode(block)
	if err != nil {
		logging.Error("Proposer msgBlockProposal failed.", "Round", consensus.Round, "RoundIndex", consensus.RoundIndex, err)
		return err
	}

	p.eventMux.AsyncPost(SendMessageEvent{Code: msgBlockProposal, Payload: ecp, Round: consensus.Round})
	logging.Info("send msgBlockProposal.", "Round", consensus.Round, "RoundIndex", consensus.RoundIndex, "hash", block.Hash().String())

	return nil
}

func (p *Proposal) processProposedBlockMsg(msg *CachedBlockMessage, status MsgReceivedStatus) (error, bool) { //, fromCache bool) {
	//log.Debug("processPriorityMessage.")
	p.lock.Lock()
	defer p.lock.Unlock()

	if status == msgSame && msg.block != nil && p.priorityMgr.hasBlock(msg.block.Hash()) {
		// already existed
		return fmt.Errorf("this block already exist"), false
	}

	consensusData, err := GetConsensusDataFromHeader(msg.block.Header())
	if err != nil {
		logging.Error("GetConsensusDataFromHeader msgBlockProposal failed", "err", err)
		return err, true
	}

	// check whether should gossip the proposed block.
	if status == msgSame && !p.priorityMgr.isMaxPriority(consensusData.Priority, consensusData.Round, consensusData.RoundIndex) {
		return fmt.Errorf("already has a higher priority"), false
	}

	//pubkey *ecdsa.PublicKey, data *ConsensusCommon
	data := &ConsensusCommon{
		Round:          msg.round,
		RoundIndex:     msg.roundIndex,
		Step:           uint32(Propose),
		Priority:       consensusData.Priority,
		SortitionProof: consensusData.SortitionProof,
		SubUsers:       consensusData.SubUsers,
	}
	err = p.verifyFn(msg.pubKey, data)
	if err != nil {
		logging.Error("verifyPriority msgBlockProposal failed", "err", err)
		return err, true
	}

	if status == msgSame {
		// Store the block and priority
		p.priorityMgr.update(msg.block, msg.block.Hash(), consensusData.Priority, msg.round, msg.roundIndex)
		logging.Info("Update block.", "Round", msg.round, "RoundIndex", msg.roundIndex, "block", msg.block.Hash().String())

		//if !fromCache {
		//	p.eventMux.AsyncPost(TransferMessageEvent{Code: msgBlockProposal, Payload: msg.data, Round: msg.round, PayloadHash: msg.msg.PayloadHash()})
		//}
	}

	return nil, false
}

func (p *Proposal) processPriorityMessage(msg *CachedPriorityMessage, status MsgReceivedStatus) (error, bool) { //, fromCache bool) {
	logging.Debug("processPriorityMessage.")
	p.lock.Lock()
	defer p.lock.Unlock()

	if status == msgSame {
		if p.priorityMgr.hasPriority(msg.consensus.BlockHash, msg.consensus.Priority, msg.consensus.Round, msg.consensus.RoundIndex) {
			return fmt.Errorf("already has this priority"), false
		}

		// check whether should gossip the proposed block.
		if !p.priorityMgr.isMaxPriority(msg.consensus.Priority, msg.consensus.Round, msg.consensus.RoundIndex) {
			return fmt.Errorf("already has a higher priority"), false
		}
	}

	data := &ConsensusCommon{
		Round:          msg.consensus.Round,
		RoundIndex:     msg.consensus.RoundIndex,
		Step:           uint32(Propose),
		Priority:       msg.consensus.Priority,
		SortitionProof: msg.consensus.SortitionProof,
		SubUsers:       msg.consensus.SubUsers,
	}
	err := p.verifyFn(msg.pubKey, data)
	if err != nil {
		logging.Error("verifyPriority msgPriorityProposal failed", "err", err)
		return err, true
	}

	if status == msgSame {
		// Store the block and priority
		p.priorityMgr.update(nil, msg.consensus.BlockHash, msg.consensus.Priority, msg.consensus.Round, msg.consensus.RoundIndex)
		logging.Info("Update priority.", "Round", msg.consensus.Round, "RoundIndex", msg.consensus.RoundIndex, "block", msg.consensus.BlockHash.String())

		//if !fromCache {
		//	p.eventMux.AsyncPost(TransferMessageEvent{Code: msgPriorityProposal, Payload: msg.data, Round: msg.consensus.Round, PayloadHash: msg.msg.PayloadHash()})
		//}
	}

	return nil, false
}

func (p *Proposal) blockhashWithMaxPriority(round *big.Int, roundIndex uint32) (common.Hash, common.Hash, bool) {
	return p.priorityMgr.getHashWithMaxPriority(round, roundIndex)
}

func (p *Proposal) getBlockInCache(blockHash common.Hash, priority common.Hash) *types.Block {
	return p.priorityMgr.getBlockInCache(blockHash, priority)
}
