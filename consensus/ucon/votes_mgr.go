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
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
)

type AddrVoteType uint8

const (
	addrNone     AddrVoteType = iota
	addrNotVoted AddrVoteType = iota
	addrVoteExist
	addrDifferentVote
	addrDoubleVoted
)

type VoteSta struct {
	lock         sync.Mutex
	votesInfo    map[common.Hash]VotesInfoForBlockHash // key: block hash, no need to use RoundIndexHash
	voteCounts   map[common.Hash]uint32                // key: block hash, no need to use RoundIndexHash
	addressVotes map[common.Address]*AddrVoteStatus
	vtype        VoteType
}

func NewVoteSta(vtype VoteType) *VoteSta {
	p := &VoteSta{
		votesInfo:    make(map[common.Hash]VotesInfoForBlockHash),
		voteCounts:   make(map[common.Hash]uint32),
		addressVotes: make(map[common.Address]*AddrVoteStatus),
		vtype:        vtype,
	}
	return p
}

func (v *VoteSta) clear() {
	v.lock.Lock()
	defer v.lock.Unlock()

	v.votesInfo = make(map[common.Hash]VotesInfoForBlockHash)
	v.voteCounts = make(map[common.Hash]uint32)
	v.addressVotes = make(map[common.Address]*AddrVoteStatus)
}

func (v *VoteSta) newVote(address common.Address, priority, hash common.Hash, vote *SingleVote) (bool, uint32) {
	v.lock.Lock()
	defer v.lock.Unlock()

	add := false
	priorityAndHash := v.addressVotes[address]
	if priorityAndHash == nil {
		v.addressVotes[address] = &AddrVoteStatus{
			Hash:        hash,
			Signature:   vote.Signature,
			DoubleVoted: false,
		}

		add = true
	}

	if add {
		// add new vote to votesInfo and voteCounts
		votesinfo := v.votesInfo[hash]
		if votesinfo == nil {
			votesinfo = NewVotesInfoForBlockHash()
			v.votesInfo[hash] = votesinfo
		}
		v.votesInfo[hash][address] = vote
		v.voteCounts[hash] += vote.Votes
	}

	return add, v.voteCounts[hash]
}

func (v *VoteSta) addrVoteInfo(address common.Address, hash common.Hash) (AddrVoteType, *AddrVoteStatus) {
	v.lock.Lock()
	defer v.lock.Unlock()

	priorityAndHash := v.addressVotes[address]
	if priorityAndHash == nil {
		return addrNotVoted, priorityAndHash
	}

	if priorityAndHash.DoubleVoted {
		return addrDoubleVoted, priorityAndHash
	}

	r := CompareCommonHash(priorityAndHash.Hash, hash)
	if r == 0 || v.vtype == NextIndex {
		return addrVoteExist, priorityAndHash
	} else {
		priorityAndHash.DoubleVoted = true

		logging.Error("DoubleSign.", "Addr", address.String(), "Hash1", priorityAndHash.Hash.String(), "Hash2", hash.String())

		// this is a malicious node, remove its vote from votesInfo
		vote := v.votesInfo[priorityAndHash.Hash][address]
		if vote != nil {
			v.voteCounts[priorityAndHash.Hash] -= vote.Votes
			delete(v.votesInfo[priorityAndHash.Hash], address)
		}

		return addrDifferentVote, priorityAndHash
	}
}

func (v *VoteSta) getVotesInfo(hash common.Hash) (VotesInfoForBlockHash, uint32) {
	v.lock.Lock()
	defer v.lock.Unlock()

	votes := NewVotesInfoForBlockHash()
	for addr, vote := range v.votesInfo[hash] {
		votes[addr] = vote
	}
	count := v.voteCounts[hash]

	return votes, count
}

func (v *VoteSta) getVotesCount() map[common.Hash]uint32 {
	v.lock.Lock()
	defer v.lock.Unlock()

	counts := make(map[common.Hash]uint32)
	for hash, vote := range v.voteCounts {
		counts[hash] = vote
	}

	return counts
}

type VotesManager struct {
	round        *big.Int
	roundIndex   uint32
	prevotes     *VoteSta
	precommits   *VoteSta
	nextIndexs   *VoteSta
	certificates *VoteSta
}

func NewVotesManager() *VotesManager {
	vm := &VotesManager{
		prevotes:     NewVoteSta(Prevote),
		precommits:   NewVoteSta(Precommit),
		nextIndexs:   NewVoteSta(NextIndex),
		certificates: NewVoteSta(Certificate),
	}
	return vm
}

func (vm *VotesManager) clearVotesInfo(round *big.Int, roundIndex uint32) { //, newRound *big.Int, validator uint64, voteProportion float64) {
	vm.round = round
	vm.roundIndex = roundIndex
	vm.prevotes.clear()
	vm.precommits.clear()
	vm.nextIndexs.clear()
	vm.certificates.clear()
}

func (vm *VotesManager) getVotes(vtype VoteType, hash common.Hash) (VotesInfoForBlockHash, uint32) {
	switch vtype {
	case Prevote:
		return vm.prevotes.getVotesInfo(hash)
	case Precommit:
		return vm.precommits.getVotesInfo(hash)
	case NextIndex:
		return vm.nextIndexs.getVotesInfo(hash)
	case Certificate:
		return vm.certificates.getVotesInfo(hash)
	}
	return nil, 0
}

func (vm *VotesManager) getVotesCount(vtype VoteType, round *big.Int, roundIndex uint32) map[common.Hash]uint32 {
	if round == nil || vm.roundIndex != roundIndex || (vm.round != nil && round.Cmp(vm.round) != 0) {
		return nil
	}
	switch vtype {
	case Prevote:
		return vm.prevotes.getVotesCount()
	case Precommit:
		return vm.precommits.getVotesCount()
	case NextIndex:
		return vm.nextIndexs.getVotesCount()
	case Certificate:
		return vm.certificates.getVotesCount()
	}
	return nil
}

func (vm *VotesManager) newVote(round *big.Int, roundIndex uint32, vtype VoteType, address common.Address, priority, hash common.Hash, vote *SingleVote) (bool, uint32) {
	if round == nil || vote == nil || round.Cmp(vm.round) != 0 || roundIndex != vm.roundIndex {
		return false, 0
	}

	//log.Info("NewVote.", "Round", round, "RoundIndex", roundIndex, "Sub-Users", vote.Votes, "VoteType", uint32(vtype), "addr", address.String())
	switch vtype {
	case Prevote:
		return vm.prevotes.newVote(address, priority, hash, vote)
	case Precommit:
		return vm.precommits.newVote(address, priority, hash, vote)
	case NextIndex:
		return vm.nextIndexs.newVote(address, priority, hash, vote)
	case Certificate:
		return vm.certificates.newVote(address, priority, hash, vote)
	}
	return false, 0
}

func (vm *VotesManager) addrVoteInfo(round *big.Int, roundIndex uint32, vtype VoteType, address common.Address, hash common.Hash) (AddrVoteType, *AddrVoteStatus) {
	if round == nil || round.Cmp(vm.round) != 0 || roundIndex != vm.roundIndex {
		return addrNone, nil
	}

	switch vtype {
	case Prevote:
		return vm.prevotes.addrVoteInfo(address, hash)
	case Precommit:
		return vm.precommits.addrVoteInfo(address, hash)
	case NextIndex:
		return vm.nextIndexs.addrVoteInfo(address, hash)
	case Certificate:
		return vm.certificates.addrVoteInfo(address, hash)
	}
	return addrNone, nil
}

type VotesWrapper struct {
	chamber *VotesManager
	house   *VotesManager
}

func NewVotesWrapper() *VotesWrapper {
	vw := &VotesWrapper{
		chamber: NewVotesManager(),
		house:   NewVotesManager(),
	}
	return vw
}

func (vw *VotesWrapper) newVote(round *big.Int, roundIndex uint32, vtype VoteType, address common.Address, priority, hash common.Hash, vote *SingleVote, validatorType params.ValidatorKind) (bool, uint32) {
	var tmp *VotesManager
	if validatorType == params.KindChamber {
		tmp = vw.chamber
	} else if validatorType == params.KindHouse {
		tmp = vw.house
	}

	if tmp != nil {
		return tmp.newVote(round, roundIndex, vtype, address, priority, hash, vote)
	}
	return false, uint32(0)
}

func (vw *VotesWrapper) addrVoteInfo(round *big.Int, roundIndex uint32, vtype VoteType, address common.Address, hash common.Hash, validatorType params.ValidatorKind) (AddrVoteType, *AddrVoteStatus) {
	var tmp *VotesManager
	if validatorType == params.KindChamber {
		tmp = vw.chamber
	} else if validatorType == params.KindHouse {
		tmp = vw.house
	}
	if tmp != nil {
		return tmp.addrVoteInfo(round, roundIndex, vtype, address, hash)
	}
	return addrNone, nil
}

func (vw *VotesWrapper) getVotes(vtype VoteType, hash common.Hash, validatorType params.ValidatorKind) (VotesInfoForBlockHash, uint32) {
	var tmp *VotesManager
	if validatorType == params.KindChamber {
		tmp = vw.chamber
	} else if validatorType == params.KindHouse {
		tmp = vw.house
	}
	if tmp != nil {
		return tmp.getVotes(vtype, hash)
	}
	return nil, uint32(0)
}

func (vw *VotesWrapper) clearVotesInfo(round *big.Int, roundIndex uint32) {
	vw.chamber.clearVotesInfo(round, roundIndex)
	vw.house.clearVotesInfo(round, roundIndex)
}

func (vw *VotesWrapper) existHashOverVotesThreshold(round *big.Int, roundIndex uint32, chamberTh, houseTh uint32) bool {
	checkCount := func(voteType VoteType) bool {
		chamberCounts := vw.chamber.getVotesCount(voteType, round, roundIndex)
		if chamberCounts == nil {
			return false
		}

		houseCounts := vw.house.getVotesCount(voteType, round, roundIndex)
		if houseCounts == nil {
			return false
		}

		chamberTotal, houseTotal := uint32(0), uint32(0)
		for _, ca := range chamberCounts {
			chamberTotal += ca
		}

		for _, ch := range houseCounts {
			houseTotal += ch
			//if houseTotal > houseTh {
			//	return true
			//}
		}

		if chamberTotal >= chamberTh && houseTotal >= houseTh {
			return true
		}
		return false
	}

	if checkCount(Prevote) {
		return true
	}

	if checkCount(Precommit) {
		return true
	}

	return false
}

type VotesWrapperList struct {
	wrappers []*VotesWrapper //map[RoundIndexHash]*VotesWrapper
	//round *big.Int
	//roundIndex uint32
	contexts []RoundIndexHash
}

func NewVotesWrapperList() *VotesWrapperList {
	v := VotesWrapperList{
		wrappers: []*VotesWrapper{}, //make(map[RoundIndexHash]*VotesWrapper),
		contexts: []RoundIndexHash{},
	}
	return &v
}

func (v *VotesWrapperList) GetWrapper(round *big.Int, roundIndex uint32) *VotesWrapper {
	riHash := GenerateRoundIndexHash(round.Uint64(), roundIndex)
	index := len(v.contexts)
	for i, item := range v.contexts {
		if item == riHash {
			index = i
			break
		}
	}
	if index < len(v.contexts) && len(v.wrappers) > index {
		return v.wrappers[index]
	}
	return nil
}

func (v *VotesWrapperList) NewWrapper(round *big.Int, roundIndex uint32) *VotesWrapper {
	old := v.GetWrapper(round, roundIndex)
	if old != nil {
		return old
	}

	riHash := GenerateRoundIndexHash(round.Uint64(), roundIndex)
	count := len(v.contexts)
	if count < params.MaxVoteCacheCount {
		wrapper := NewVotesWrapper()
		wrapper.clearVotesInfo(round, roundIndex)
		v.wrappers = append(v.wrappers, wrapper)
		v.contexts = append(v.contexts, riHash)

		logging.Info("VotesWrapper.", "context", v.contexts)

		return wrapper
	} else {
		wrapper := v.wrappers[0]
		wrapper.clearVotesInfo(round, roundIndex)

		for i := 0; i < count-1; i++ {
			v.contexts[i] = v.contexts[i+1]
			v.wrappers[i] = v.wrappers[i+1]
		}
		v.contexts[count-1] = riHash
		v.wrappers[count-1] = wrapper

		logging.Info("VotesWrapper.", "context", v.contexts)

		return wrapper
	}
}
