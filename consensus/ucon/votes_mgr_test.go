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
	"testing"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
)

func TestNewVotesManager(t *testing.T) {
	vm := NewVotesManager()

	round := big.NewInt(1)
	roundIndex := uint32(1)
	vm.clearVotesInfo(round, roundIndex)

	rawSk, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(rawSk.PublicKey)
	logging.Info("", "addr", addr.String())
	priority := common.Hash{0x01}
	hash := common.Hash{0x10}
	voteInfo := &SingleVote{
		Votes:     uint32(1),
		Signature: []byte{0x011},
		Proof:     []byte{0x011},
	}
	vm.newVote(round, roundIndex, Prevote, addr, priority, hash, voteInfo)
	vm.newVote(round, roundIndex, Precommit, addr, priority, hash, voteInfo)
	vm.newVote(round, roundIndex, NextIndex, addr, priority, hash, voteInfo)

	r, _ := vm.addrVoteInfo(round, roundIndex, Prevote, addr, hash)
	logging.Info("addrVoteInfo", "r", r)

	r, _ = vm.addrVoteInfo(round, roundIndex, Prevote, common.Address{0x11}, hash)
	logging.Info("addrVoteInfo", "r", r)

	tmp, _ := vm.getVotes(Prevote, hash)
	for k, v := range tmp {
		logging.Info(k.String(), "Votes", v.Votes)
	}
}
