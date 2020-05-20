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

	"github.com/youchainhq/go-youchain/bls"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/youdb"
)

var tmpBlock *types.Block

func TestNewVoter(t *testing.T) {
	rawSk, _ := crypto.GenerateKey()
	blsSk, _ := bls.NewBlsManager().GenerateKey()
	eventMux := new(event.TypeMux)

	db := youdb.NewMemDatabase()
	pmgr := &fakeParamsMgr{db: db}
	v := NewVoter(db, rawSk, blsSk, eventMux, verifySortition, isValidator, blockhashWithMaxPriority, getBlockInCache, getLookbackStakeInfo, getLookbackValidatorsCount, pmgr)
	v.Start(pmgr)

	ticker := time.NewTicker(pmgr.CurrentCaravelParams().ConsensusStepInterval)
	defer ticker.Stop()
	round := big.NewInt(1)
	roundIndex := uint32(2)
	count := uint32(0)
	num := 0

	tmpBlock = newBlock(round, roundIndex, common.Hash{0x01}, rawSk)

	for {
		select {
		case <-ticker.C:
			eventMux.AsyncPost(ContextChangeEvent{Round: round, RoundIndex: roundIndex, Step: count})
			logging.Debug("tick", "Round", round, "RoundIndex", roundIndex, "Step", count)
			switch count {
			case UConStepStart:

			case UConStepProposal:
				//b1 := newBlock(round, roundIndex, common.Hash{0x01}, rawSk)
				//eventMux.AsyncPost(BlockProposalEvent{Block: b1})

			case UConStepPrevote:
				//handleMsg(mh)

			case UConStepPrecommit:

			}
			count += 1
			if count > UConStepPrecommit+1 {
				//round.SetUint64(round.Uint64() + 1)
				roundIndex += 1
				count = uint32(0)
			}
			num += 1
			if num > 30 {
				return
			}
		}
	}
}

func verifySortition(pubKey *ecdsa.PublicKey, data *SortitionData, lbtype params.LookBackType) error {
	return nil
}

func isValidator(round *big.Int, roundIndex uint32, step uint32, lbtype params.LookBackType) (bool, *StepView) {
	sv := &StepView{
		SeedValue: common.Hash{0x01},
		//SeedProof:      []byte{0x01},
		//SortitionValue: common.Hash{0x01},
		SortitionProof: []byte{0x01},
		Priority:       common.Hash{0x01},
		SubUsers:       uint32(1),
		ValidatorType:  params.KindChamber,
	}
	return true, sv
}

func blockhashWithMaxPriority(round *big.Int, roundIndex uint32) (common.Hash, common.Hash, bool) {
	logging.Debug("blockhashWithMaxPriority.", "Round", round, "RoundIndex", roundIndex, "block", tmpBlock.Hash().String())
	return common.Hash{0x01}, tmpBlock.Hash(), true
}

func getBlockInCache(blockHash common.Hash, priority common.Hash) *types.Block {
	logging.Debug("getBlockInCache.", "block", blockHash.String(), "priority", priority.String())
	return tmpBlock
}

//func OverThreshold(voteType VoteType, count uint32) bool {
//	log.Debug("OverThreshold.", "voteType", voteTypeToString(voteType), "count", count)
//	return true
//}

func voteTypeToString(voteType VoteType) string {
	switch voteType {
	case Prevote:
		return "Prevote"
	case Precommit:
		return "Precommit"
	case NextIndex:
		return "NextIndex"
	}
	return "None"
}

func getLookbackStakeInfo(round *big.Int, addr common.Address, isProposer bool, lbtype params.LookBackType) (*big.Int, *big.Int, uint64, params.ValidatorKind, uint8, error) {
	return big.NewInt(0), big.NewInt(0), uint64(0), params.KindChamber, params.ValidatorOnline, nil
}

func getLookbackValidatorsCount(round *big.Int, kind params.ValidatorKind, lbtype params.LookBackType) (count uint64) {
	return 0
}

type fakeParamsMgr struct {
	db youdb.Database
}

func (f *fakeParamsMgr) CurrentCaravelParams() *params.CaravelParams {
	yp := params.Versions[params.YouCurrentVersion]
	yp.EnableBls = false // for the need of the test case
	return &yp.CaravelParams
}
func (f *fakeParamsMgr) CertificateParams(round *big.Int) (*params.CaravelParams, error) {
	return f.CurrentCaravelParams(), nil
}

func (f *fakeParamsMgr) GetLookBackVldReader(cp *params.CaravelParams, num *big.Int, lbType params.LookBackType) (state.ValidatorReader, error) {
	return state.New(common.Hash{}, common.Hash{}, common.Hash{}, state.NewDatabase(f.db))
}
