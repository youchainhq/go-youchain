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
	"testing"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
)

func TestNewProposal(t *testing.T) {
	t.SkipNow() //run on need
	loops := 100
	if testing.Short() {
		loops = 10
	}
	reader := &chainReader{}
	yp, _ := reader.VersionForRound(0)
	eventMux := new(event.TypeMux)
	rawSk, _ := crypto.GenerateKey()

	p := NewProposal(eventMux, verifyPriority, startVote)
	p.Start()

	mh := NewMessageHandler(rawSk, eventMux, getLookBackValidator, processReceivedMsg,
		processPriorityMessage, processProposedBlockMsg, processVoteMsg)
	mh.Start()

	ticker := time.NewTicker(yp.ConsensusTimeout)
	defer ticker.Stop()
	round := big.NewInt(1)
	roundIndex := uint32(1)
	count := uint32(0)
	num := 0
	for {
		select {
		case <-ticker.C:
			eventMux.AsyncPost(ContextChangeEvent{Round: round, RoundIndex: roundIndex, Step: count})
			logging.Debug("round info", "Round", round, "RoundIndex", roundIndex, "step", count)
			switch count {
			case UConStepStart:

			case UConStepProposal:
				b1 := newBlock(round, roundIndex, common.Hash{0x01}, rawSk)
				eventMux.AsyncPost(BlockProposalEvent{Block: b1})

			case UConStepPrevote:
				handleMsg(mh)

			case UConStepPrecommit:

			}
			count += 1
			if count > UConStepPrecommit+1 {
				round.SetUint64(round.Uint64() + 1)
				count = uint32(0)
			}
			num += 1
			if num > loops {
				return
			}
		}
	}
}

func verifyPriority(pubkey *ecdsa.PublicKey, data *ConsensusCommon) error {

	return nil
}

func startVote(round *big.Int, roundIndex uint32) bool {
	return false
}
