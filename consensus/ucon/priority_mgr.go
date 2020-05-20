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
	"math/big"
	"sync"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/logging"
)

type PriorityForRound map[common.Hash]common.Hash

type PriorityManager struct {
	lock        *sync.Mutex
	blocks      map[common.Hash]*types.Block // received proposed blocks from proposers in current Round
	priorities  map[RoundIndexHash]PriorityForRound
	maxPriority map[RoundIndexHash]common.Hash
	round       *big.Int
}

func NewPriorityMgr() *PriorityManager {
	return &PriorityManager{
		lock:        new(sync.Mutex),
		blocks:      make(map[common.Hash]*types.Block),
		priorities:  make(map[RoundIndexHash]PriorityForRound),
		maxPriority: make(map[RoundIndexHash]common.Hash),
		round:       big.NewInt(0),
	}
}

func (pm *PriorityManager) clearData(round *big.Int) {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	//logging.Debug("PriorityManager clearData start.", "Round", round, "CurRound", pm.round)

	if round == nil { //|| (round != nil && round.Cmp(pm.round) == 0) {
		return
	}
	pm.round = round

	pm.blocks = make(map[common.Hash]*types.Block)
	pm.priorities = make(map[RoundIndexHash]PriorityForRound)
	pm.maxPriority = make(map[RoundIndexHash]common.Hash)

	//logging.Debug("PriorityManager clearData finished.", "Round", round)
}

func (pm *PriorityManager) update(block *types.Block, blockHash, priority common.Hash, round *big.Int, roundIndex uint32) bool {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	if round == nil { //|| round.Cmp(pm.round) != 0 {
		return false
	}

	isLarger := false
	roundHash := GenerateRoundIndexHash(round.Uint64(), roundIndex)
	priorities := pm.priorities[roundHash]
	if priorities == nil {
		pm.priorities[roundHash] = make(map[common.Hash]common.Hash)
	}

	if CompareCommonHash(priority, pm.maxPriority[roundHash]) >= 0 {
		logging.Debug("update proposed block with max priority.", "hash", blockHash.String())
		pm.maxPriority[roundHash] = priority
		isLarger = true
	}

	pm.priorities[roundHash][priority] = blockHash
	if block != nil && pm.blocks[block.Hash()] == nil {
		pm.blocks[block.Hash()] = block
		//	logging.Debug("Update block.", "Round", round, "RoundIndex", roundIndex, "block", block.Hash().String(), "priority", priority.String())
		//} else {
		//	logging.Debug("Update priority.", "Round", round, "RoundIndex", roundIndex, "priority", priority.String())
	}

	return isLarger
}

func (pm *PriorityManager) getHashWithMaxPriority(round *big.Int, roundIndex uint32) (common.Hash, common.Hash, bool) {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	if round == nil {
		return common.Hash{}, common.Hash{}, false
	}

	roundHash := GenerateRoundIndexHash(round.Uint64(), roundIndex)
	priorities := pm.priorities[roundHash]
	if priorities != nil && len(priorities) > 0 {
		//logging.Debug("getHashWithMaxPriority.", "Round", round, "RoundIndex", roundIndex, "block", priorities[pm.maxPriority[roundHash]].String(), "priority", pm.maxPriority[roundHash].String())
		return pm.maxPriority[roundHash], priorities[pm.maxPriority[roundHash]], true
	}

	return common.Hash{}, common.Hash{}, false
}

func (pm *PriorityManager) getBlockInCache(blockHash common.Hash, priority common.Hash) *types.Block {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	return pm.blocks[blockHash]
}

func (pm *PriorityManager) hasBlock(blockHash common.Hash) bool {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	if pm.blocks != nil && pm.blocks[blockHash] != nil {
		// already existed
		return true
	}
	return false
}

func (pm *PriorityManager) hasPriority(blockHash, priority common.Hash, round *big.Int, roundIndex uint32) bool {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	if round == nil {
		return false
	}

	roundHash := GenerateRoundIndexHash(round.Uint64(), roundIndex)
	priorities := pm.priorities[roundHash]
	if priorities == nil || len(priorities) == 0 || CompareCommonHash(blockHash, priorities[priority]) != 0 {
		return false
	}
	return true
}

func (pm *PriorityManager) isMaxPriority(priority common.Hash, round *big.Int, roundIndex uint32) bool {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	if round == nil {
		return false
	}

	roundHash := GenerateRoundIndexHash(round.Uint64(), roundIndex)
	priorities := pm.priorities[roundHash]
	if priorities == nil || len(pm.priorities) == 0 || CompareCommonHash(priority, pm.maxPriority[roundHash]) >= 0 {
		//log.Info("update proposed block with max priority.", "hash", blockHash.String())
		return true
	}
	return false
}
