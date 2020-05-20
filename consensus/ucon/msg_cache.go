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
	"crypto/ecdsa"
	"math/big"
	"sync"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto/vrf"
)

//type AddrCachedMsgInfo struct {
//	//lock            sync.Mutex
//	maxRound        uint64
//	maxRI           uint32
//	alreadyExist    map[MsgType](map[RoundIndexHash]bool)
//	cachedNextIndex map[RoundIndexHash]uint8
//	times           *list.List
//	avgInterval     uint64
//	lastTime        uint64 // milliseconds
//}
//
//func NewAddrCachedMsgInfo() *AddrCachedMsgInfo {
//	a := &AddrCachedMsgInfo{
//		alreadyExist:    make(map[MsgType](map[RoundIndexHash]bool)),
//		cachedNextIndex: make(map[RoundIndexHash]uint8),
//		times:           list.New(),
//	}
//	a.alreadyExist[msgPriorityProposal] = make(map[RoundIndexHash]bool)
//	a.alreadyExist[msgBlockProposal] = make(map[RoundIndexHash]bool)
//	a.alreadyExist[msgPrevote] = make(map[RoundIndexHash]bool)
//	a.alreadyExist[msgPrecommit] = make(map[RoundIndexHash]bool)
//
//	return a
//}
//
//func (a *AddrCachedMsgInfo) NewMsg(msg CachedMessage, code MsgType, timestamp time.Time) bool {
//	//a.lock.Lock()
//	//defer a.lock.Unlock()
//
//	round, roundIndex := msg.GetContext()
//	if round != nil && (round.Uint64() < a.maxRound || (round.Uint64() == a.maxRound && roundIndex < a.maxRI)) {
//		return false
//	}
//
//	riHash := GenerateRoundIndexHash(round.Uint64(), roundIndex)
//	if code == msgNext && a.cachedNextIndex[riHash] > 2 {
//		return false
//	} else if code != msgNext && a.alreadyExist[code][riHash] == true {
//		return false
//	}
//
//	// judge the time interval
//	millisecondTime := uint64(timestamp.UnixNano() / 1e6)
//	if a.times.Len() == 0 && a.lastTime == 0 {
//		a.lastTime = millisecondTime
//	} else {
//		if millisecondTime < a.lastTime {
//			return false
//		}
//		timeInterval := millisecondTime - a.lastTime
//		if a.times.Len() == 10 {
//			tmp := a.avgInterval
//			tmp = tmp + (timeInterval-a.times.Front().Value.(uint64))/10
//			if tmp < 100 {
//				return false
//			}
//
//			first := a.times.Front()
//			a.times.Remove(first)
//			a.avgInterval = tmp
//		} else {
//			a.avgInterval = (a.avgInterval*uint64(a.times.Len()) + timeInterval) / uint64(a.times.Len()+1)
//		}
//
//		a.times.PushBack(timeInterval)
//		a.lastTime = millisecondTime
//	}
//
//	if code == msgNext {
//		a.cachedNextIndex[riHash] = a.cachedNextIndex[riHash] + 1
//	} else {
//		a.alreadyExist[code][riHash] = true
//	}
//
//	return true
//}
//
//func (a *AddrCachedMsgInfo) ClearMsg(round uint64, roundIndex uint32) bool {
//	//a.lock.Lock()
//	//defer a.lock.Unlock()
//
//	deleteFn := func(data map[RoundIndexHash]bool) {
//		for hash, _ := range data {
//			r, ri := GetInfoFromHash(hash)
//			if r < round || (r == round && ri < roundIndex) {
//				delete(data, hash)
//			}
//		}
//	}
//	deleteFn(a.alreadyExist[msgPriorityProposal])
//	deleteFn(a.alreadyExist[msgBlockProposal])
//	deleteFn(a.alreadyExist[msgPrevote])
//	deleteFn(a.alreadyExist[msgPrecommit])
//
//	for hash, _ := range a.cachedNextIndex {
//		r, ri := GetInfoFromHash(hash)
//		if r < round || (r == round && ri < roundIndex) {
//			delete(a.cachedNextIndex, hash)
//		}
//	}
//	if a.maxRound < round || (a.maxRound == round && a.maxRI < roundIndex) {
//		a.maxRound = round
//		a.maxRI = roundIndex
//	}
//
//	return true
//}

type CachedMessage interface {
	GetContext() (*big.Int, uint32)
	Hash() common.Hash
}

type CachedBlockMessage struct {
	data       []byte
	msg        *Message
	pubKey     *ecdsa.PublicKey
	vrfPK      vrf.PublicKey
	block      *types.Block
	round      *big.Int
	roundIndex uint32
}

func (m *CachedBlockMessage) GetContext() (*big.Int, uint32) {
	return m.round, m.roundIndex
}

func (m *CachedBlockMessage) Hash() common.Hash {
	if m.block == nil {
		return common.Hash{}
	}
	return m.block.Hash()
}

type CachedPriorityMessage struct {
	data      []byte
	msg       *Message
	pubKey    *ecdsa.PublicKey
	vrfPK     vrf.PublicKey
	consensus *ConsensusCommon
}

func (m *CachedPriorityMessage) GetContext() (*big.Int, uint32) {
	if m.consensus != nil {
		return m.consensus.Round, m.consensus.RoundIndex
	}
	return big.NewInt(0), 0
}

func (m *CachedPriorityMessage) Hash() common.Hash {
	if m.consensus == nil {
		return common.Hash{}
	}
	return m.consensus.BlockHash
}

type CachedVotesMessage struct {
	data      []byte
	msg       *Message
	VotesData *BlockHashWithVotes
	addr      common.Address
}

func (m *CachedVotesMessage) GetContext() (*big.Int, uint32) {
	if m.VotesData != nil {
		return m.VotesData.Round, m.VotesData.RoundIndex
	}
	return big.NewInt(0), 0
}

func (m *CachedVotesMessage) Hash() common.Hash {
	if m.VotesData == nil {
		return common.Hash{}
	}
	return m.VotesData.BlockHash
}

type CachedMsgs []CachedMessage

const MaxCachedMsgsCount = 1024

type TypedCacheMsgs struct {
	//lock       sync.Mutex
	msgs       map[uint64](map[uint32]CachedMsgs) // Round, RoundIndex
	round      uint64
	roundIndex uint32
}

func NewTypedCacheMsgs() *TypedCacheMsgs {
	m := &TypedCacheMsgs{
		msgs: make(map[uint64](map[uint32]CachedMsgs), MaxCachedMsgsCount),
	}
	return m
}

func (m *TypedCacheMsgs) NewMessage(msg CachedMessage) {
	//m.lock.Lock()
	//defer m.lock.Unlock()

	round, roundIndex := msg.GetContext()
	if round != nil && (m.round > round.Uint64() || (m.round == round.Uint64() && m.roundIndex >= roundIndex)) {
		return
	}

	if len(m.msgs) == MaxCachedMsgsCount {
		//m.msgs = make(map[uint64](map[uint32]CachedMsgs), MaxCachedMsgsCount)
		return
	}

	// cache this message
	roundMsgs := m.msgs[round.Uint64()]
	if roundMsgs == nil {
		roundMsgs = make(map[uint32]CachedMsgs)
		m.msgs[round.Uint64()] = roundMsgs
	}
	riMsgs := m.msgs[round.Uint64()][roundIndex]
	if riMsgs == nil {
		riMsgs = CachedMsgs{}
		m.msgs[round.Uint64()][roundIndex] = riMsgs
	}

	m.msgs[round.Uint64()][roundIndex] = append(riMsgs, CachedMsgs{msg}...)
}

func (m *TypedCacheMsgs) Clear(round uint64, roundIndex uint32) {
	//m.lock.Lock()
	//defer m.lock.Unlock()

	m.round = round
	m.roundIndex = roundIndex

	for r, rmsgs := range m.msgs {
		if r < round {
			delete(m.msgs, r)
		} else if r == round {
			for ri, _ := range rmsgs {
				if ri < roundIndex {
					delete(rmsgs, ri)
				}
			}
		}
	}
}

func (m *TypedCacheMsgs) GetMessages(round uint64, roundIndex uint32) CachedMsgs {
	//m.lock.Lock()
	//defer m.lock.Unlock()

	if m.msgs[round] == nil {
		return CachedMsgs{}
	}
	riMsgs := m.msgs[round][roundIndex]
	if riMsgs == nil {
		return CachedMsgs{}
	}
	return riMsgs
}

func (m *TypedCacheMsgs) RemoveMessages(round uint64, roundIndex uint32) {
	//m.lock.Lock()
	//defer m.lock.Unlock()

	if m.msgs[round] == nil || m.msgs[round][roundIndex] == nil {
		return
	}
	delete(m.msgs[round], roundIndex)
}

// future round's message cache
type CachedMsgMgr struct {
	lock          sync.Mutex
	blockMsgs     *TypedCacheMsgs
	priorityMsgs  *TypedCacheMsgs
	prevoteMsgs   *TypedCacheMsgs
	precommitMsgs *TypedCacheMsgs
	nextMsgs      *TypedCacheMsgs
	//addrMsgsInfo  map[common.Address]*AddrCachedMsgInfo
}

func InitCachedMessages() *CachedMsgMgr {
	cache := &CachedMsgMgr{
		blockMsgs:     NewTypedCacheMsgs(),
		priorityMsgs:  NewTypedCacheMsgs(),
		prevoteMsgs:   NewTypedCacheMsgs(),
		precommitMsgs: NewTypedCacheMsgs(),
		nextMsgs:      NewTypedCacheMsgs(),
		//addrMsgsInfo:  make(map[common.Address]*AddrCachedMsgInfo),
	}
	return cache
}

func (c *CachedMsgMgr) NewMessage(msg CachedMessage, code MsgType, addr common.Address, timestamp time.Time) {
	if code < msgPriorityProposal || code > msgNext {
		return
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	//// add info into AddrCachedMsgInfo, if failed, then return
	//if c.addrMsgsInfo[addr] == nil {
	//	c.addrMsgsInfo[addr] = NewAddrCachedMsgInfo()
	//	c.addrMsgsInfo[addr].NewMsg(msg, code, timestamp)
	//} else {
	//	result := c.addrMsgsInfo[addr].NewMsg(msg, code, timestamp)
	//	logging.Info("AvgInterval", "cached", c.addrMsgsInfo[addr].avgInterval, "addr", addr.String())
	//	if !result {
	//		return
	//	}
	//}

	switch code {
	case msgBlockProposal:
		c.blockMsgs.NewMessage(msg)
	case msgPriorityProposal:
		c.priorityMsgs.NewMessage(msg)
	case msgPrevote:
		c.prevoteMsgs.NewMessage(msg)
	case msgPrecommit:
		c.precommitMsgs.NewMessage(msg)
	case msgNext:
		c.nextMsgs.NewMessage(msg)
	}
}

func (c *CachedMsgMgr) Clear(round uint64, roundIndex uint32) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.blockMsgs.Clear(round, roundIndex)
	c.priorityMsgs.Clear(round, roundIndex)
	c.prevoteMsgs.Clear(round, roundIndex)
	c.precommitMsgs.Clear(round, roundIndex)
	c.nextMsgs.Clear(round, roundIndex)

	//for addr, _ := range c.addrMsgsInfo {
	//	c.addrMsgsInfo[addr].ClearMsg(round, roundIndex)
	//}
}

func (c *CachedMsgMgr) GetMessages(round uint64, roundIndex uint32, code MsgType) CachedMsgs {
	c.lock.Lock()
	defer c.lock.Unlock()

	switch code {
	case msgBlockProposal:
		return c.blockMsgs.GetMessages(round, roundIndex)
	case msgPriorityProposal:
		return c.priorityMsgs.GetMessages(round, roundIndex)
	case msgPrevote:
		return c.prevoteMsgs.GetMessages(round, roundIndex)
	case msgPrecommit:
		return c.precommitMsgs.GetMessages(round, roundIndex)
	case msgNext:
		return c.nextMsgs.GetMessages(round, roundIndex)
	}
	return CachedMsgs{}
}

func (c *CachedMsgMgr) RemoveMessages(round uint64, roundIndex uint32, code MsgType) {
	c.lock.Lock()
	defer c.lock.Unlock()

	switch code {
	case msgBlockProposal:
		c.blockMsgs.RemoveMessages(round, roundIndex)
	case msgPriorityProposal:
		c.priorityMsgs.RemoveMessages(round, roundIndex)
	case msgPrevote:
		c.prevoteMsgs.RemoveMessages(round, roundIndex)
	case msgPrecommit:
		c.precommitMsgs.RemoveMessages(round, roundIndex)
	case msgNext:
		c.nextMsgs.RemoveMessages(round, roundIndex)
	}
}
