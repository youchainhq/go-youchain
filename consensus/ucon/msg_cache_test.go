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
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/logging"
)

func TestGetSignatureAddress(t *testing.T) {
	round := big.NewInt(257)
	index := uint32(1)

	hash := GenerateRoundIndexHash(round.Uint64(), index)
	logging.Info("GenerateRoundIndexHash", "hash", hash)
}

func TestInitCachedMessages(t *testing.T) {
	addr := common.Address{0x011}
	cache := InitCachedMessages()
	cache.Clear(uint64(0), uint32(0))

	m11 := &CachedBlockMessage{
		round:      big.NewInt(1),
		roundIndex: uint32(1),
		data:       []byte{0x011},
	}
	m12 := &CachedBlockMessage{
		round:      big.NewInt(1),
		roundIndex: uint32(2),
		data:       []byte{0x012},
	}
	m21 := &CachedBlockMessage{
		round:      big.NewInt(2),
		roundIndex: uint32(1),
		data:       []byte{0x021},
	}
	m22 := &CachedBlockMessage{
		round:      big.NewInt(2),
		roundIndex: uint32(2),
		data:       []byte{0x022},
	}
	cache.NewMessage(m11, msgBlockProposal, addr, time.Now())
	cache.NewMessage(m12, msgBlockProposal, addr, time.Now())
	cache.NewMessage(m21, msgBlockProposal, addr, time.Now())
	cache.NewMessage(m22, msgBlockProposal, addr, time.Now())

	tmp11 := cache.GetMessages(uint64(1), uint32(1), msgBlockProposal)
	rmp11 := tmp11[0].(*CachedBlockMessage)
	logging.Info("ProposedBlockMsgs", "tmp11", rmp11.data, "m11", m11.data)
	//log.Info(tmp1[2].data, m12.data)

	tmp21 := cache.GetMessages(uint64(2), uint32(1), msgBlockProposal)
	rmp21 := tmp21[0].(*CachedBlockMessage)
	logging.Info("ProposedBlockMsgs", "tmp21", rmp21.data, "m21", m21.data)

	cache.RemoveMessages(uint64(1), uint32(1), msgBlockProposal)
	tmp13 := cache.GetMessages(uint64(1), uint32(1), msgBlockProposal)
	if len(tmp13) == 0 {
		logging.Info("remove proposed-block succeed")
	}

	mv11 := &CachedVotesMessage{
		data:      []byte{0x011},
		msg:       &Message{},
		VotesData: &BlockHashWithVotes{Round: big.NewInt(1), RoundIndex: uint32(1)},
	}
	mv12 := &CachedVotesMessage{
		data:      []byte{0x012},
		msg:       &Message{},
		VotesData: &BlockHashWithVotes{Round: big.NewInt(1), RoundIndex: uint32(2)},
	}
	mv13 := &CachedVotesMessage{
		data:      []byte{0x013},
		msg:       &Message{},
		VotesData: &BlockHashWithVotes{Round: big.NewInt(1), RoundIndex: uint32(3)},
	}
	cache.NewMessage(mv11, msgPrevote, addr, time.Now())
	cache.NewMessage(mv12, msgPrecommit, addr, time.Now())
	cache.NewMessage(mv13, msgNext, addr, time.Now())

	tmpmv11 := cache.GetMessages(uint64(1), uint32(1), msgPrevote)
	if len(tmpmv11) > 0 {
		rmpmv11 := tmpmv11[0].(*CachedVotesMessage)
		logging.Info("VotesMsgs", "tmpmv11", rmpmv11.data, "mv11", mv11.data)
		//log.Info(tmpmv11[0].VotesData)
		//log.Info(tmpmv11[0].msg)
	}

	tmpmv12 := cache.GetMessages(uint64(1), uint32(2), msgPrecommit)
	if len(tmpmv12) > 0 {
		rmpmv12 := tmpmv12[0].(*CachedVotesMessage)
		logging.Info("VotesMsgs", "tmpmv12", rmpmv12.data, "mv12", mv12.data)
		//log.Info(tmpmv12[0].VotesData)
		//log.Info(tmpmv12[0].msg)
	}

	tmpmv13 := cache.GetMessages(uint64(1), uint32(3), msgNext)
	if len(tmpmv13) > 0 {
		rmpmv13 := tmpmv13[0].(*CachedVotesMessage)
		logging.Info("VotesMsgs", "tmpmv13", rmpmv13.data, "mv13", mv13.data)
		//log.Info(tmpmv13[0].VotesData)
		//log.Info(tmpmv13[0].msg)
	}

	cache.RemoveMessages(uint64(1), uint32(1), msgPrevote)
	tmpmv111 := cache.GetMessages(uint64(1), uint32(1), msgPrevote)
	if len(tmpmv111) == 0 {
		logging.Info("remove vote-msg succeed 1")
	}

	cache.RemoveMessages(uint64(1), uint32(2), msgPrecommit)
	tmpmv112 := cache.GetMessages(uint64(1), uint32(2), msgPrecommit)
	if len(tmpmv112) == 0 {
		logging.Info("remove vote-msg succeed 2")
	}

	cache.RemoveMessages(uint64(1), uint32(3), msgNext)
	tmpmv113 := cache.GetMessages(uint64(1), uint32(3), msgNext)
	if len(tmpmv113) == 0 {
		logging.Info("remove vote-msg succeed 3")
	}
}
