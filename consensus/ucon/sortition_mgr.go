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
	"github.com/youchainhq/go-youchain/crypto/vrf"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
)

type getStakeFn func(round *big.Int, addr common.Address, isProposer bool, lbType params.LookBackType) (*big.Int, *big.Int, uint64, params.ValidatorKind, uint8, error)
type getLookBackSeedFn func(round *big.Int, lbType params.LookBackType) (common.Hash, error)
type getValidatorsCountFn func(round *big.Int, kind params.ValidatorKind, lbType params.LookBackType) (count uint64)

// data structure for StepView info
type StepView struct {
	Priority       common.Hash
	SortitionProof []byte
	//SortitionValue common.Hash
	SubUsers uint32
	//SeedProof      []byte
	SeedValue     common.Hash
	ValidatorType params.ValidatorKind
	Threshold     uint64
}

type StepViews map[uint32]*StepView

func NewStepViews() StepViews {
	sv := make(map[uint32]*StepView)
	return sv
}

// one round, multiple roundIndex
type SortitionManager struct {
	lock             sync.Mutex
	stepviews        map[RoundIndexHash]StepViews
	round            *big.Int
	vrfSk            vrf.PrivateKey
	addr             common.Address
	getLookBackStake getStakeFn
	getLookBackSeed  getLookBackSeedFn
}

func NewSortitionManager(vrfSk vrf.PrivateKey, getStake getStakeFn, getLookBackSeed getLookBackSeedFn, addr common.Address) *SortitionManager {
	mgr := &SortitionManager{
		stepviews:        make(map[RoundIndexHash]StepViews),
		round:            big.NewInt(0),
		vrfSk:            vrfSk,
		getLookBackStake: getStake,
		getLookBackSeed:  getLookBackSeed,
		addr:             addr,
	}
	return mgr
}

func (sm *SortitionManager) NewStepView(round *big.Int, roundIndex uint32, step uint32, stepview *StepView) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	if round == nil || stepview == nil {
		logging.Error("Wrong step view.", "Round", round, "Current", sm.round, "Stepview", stepview)
		return
	}

	riHash := GenerateRoundIndexHash(round.Uint64(), roundIndex)
	stepviews := sm.stepviews[riHash]
	if stepviews == nil {
		sm.stepviews[riHash] = NewStepViews()
		stepviews = sm.stepviews[riHash]
	}
	stepviews[step] = stepview
	//log.Info("NewStepView.", "Round", round, "RoundIndex", roundIndex, "Step", step)
}

func (sm *SortitionManager) GetStepView(round *big.Int, roundIndex uint32, step uint32) *StepView {
	if round == nil {
		return nil
	}

	sm.lock.Lock()
	defer sm.lock.Unlock()

	riHash := GenerateRoundIndexHash(round.Uint64(), roundIndex)
	stepviews := sm.stepviews[riHash]
	if stepviews == nil {
		return nil
	}
	return stepviews[step]
}

func (sm *SortitionManager) ClearStepView(round *big.Int) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	if round == nil || round.Cmp(sm.round) == 0 {
		return
	}
	sm.round = round

	sm.stepviews = make(map[RoundIndexHash]StepViews)
}

func (sm *SortitionManager) isProposer(round *big.Int, roundIndex uint32) (bool, *StepView) {
	stepView := sm.GetStepView(round, roundIndex, UConStepProposal)
	if stepView != nil {
		if stepView.SubUsers > 0 {
			return true, stepView
		} else {
			return false, nil
		}
	}

	stake, totalStake, threshold, validatorType, _, err := sm.getLookBackStake(round, sm.addr, true, params.LookBackStake)
	if err != nil {
		logging.Error("GetLookbackStake failed.", "Round", round, "RoundIndex", roundIndex, "addr", sm.addr.String(), "err", err)
		return false, nil
	}
	if validatorType != params.KindChamber {
		logging.Error("isProposer: not a Chamber", "addr", sm.addr.String(), "type", validatorType, "stake", stake, "totalStake", totalStake, "threshold", threshold)
		return false, nil
	}

	lookBackSeed, err := sm.getLookBackSeed(round, params.LookBackPos)
	if err != nil {
		logging.Error("GetLookBackSeed failed.", "Round", round, "RoundIndex", roundIndex, "err", err)
		return false, nil
	}
	sortitionValue, proof, subUsers := VrfSortition(sm.vrfSk, lookBackSeed, roundIndex, uint32(UConStepProposal),
		threshold, stake, totalStake)
	view := &StepView{
		Priority:       VrfComputePriority(sortitionValue, subUsers),
		SortitionProof: proof,
		SubUsers:       subUsers,
		ValidatorType:  validatorType,
		Threshold:      threshold,
	}

	if subUsers > 0 {
		// compute next round's seed and self's priority, then construct message and gossip
		view.SeedValue, _ = ComputeSeed(sm.vrfSk, round, roundIndex, lookBackSeed)
		sm.NewStepView(round, roundIndex, uint32(UConStepProposal), view)

		logging.Info("---isProposer: YES.", "Round", round, "RoundIndex", roundIndex, "Kind", params.ValidatorKindToString(view.ValidatorType), "Sub-Users", subUsers,
			"stake", stake, "totalStake", totalStake, "seed", lookBackSeed.String()) //, "addr", sm.addr.String())

		//todo metrics
		return true, view
	} else {
		logging.Info("---isProposer: NO.", "Round", round, "RoundIndex", roundIndex, "Kind", params.ValidatorKindToString(view.ValidatorType), "Sub-Users", subUsers,
			"stake", stake, "totalStake", totalStake, "seed", lookBackSeed.String()) //, "addr", sm.addr.String())
		return false, view
	}
}

func (sm *SortitionManager) isValidator(round *big.Int, roundIndex uint32, step uint32, lbType params.LookBackType) (bool, *StepView) {
	stepView := sm.GetStepView(round, roundIndex, step)
	if stepView != nil {
		if stepView.SubUsers > 0 {
			return true, stepView
		} else {
			return false, stepView
		}
	}

	stake, totalStake, threshold, validatorType, status, err := sm.getLookBackStake(round, sm.addr, false, lbType)
	logging.Debug("isValidator.", "status", status, "kind", params.ValidatorKindToString(validatorType))
	if status == params.ValidatorOffline || validatorType != params.KindChamber { //(validatorType == params.KindHouse && lbType == params.LookBackCert) {
		stepView = &StepView{
			SubUsers:      0,
			ValidatorType: validatorType,
			Threshold:     threshold,
		}

		sm.NewStepView(round, roundIndex, step, stepView)
		return false, nil
	}

	if err != nil || stake == nil || totalStake == nil || totalStake.Cmp(big.NewInt(0)) <= 0 {
		logging.Error("GetStake failed.", "Round", round, "RoundIndex", roundIndex, "stake", stake, "totalStake", totalStake)
		return false, nil
	}
	lookBackSeed, err := sm.getLookBackSeed(round, lbType)
	if err != nil {
		logging.Error("processCommitMessage failed.", "Round", round, "RoundIndex", roundIndex, err)
		return false, nil
	}
	sortitionValue, proof, subUsers := VrfSortition(sm.vrfSk, lookBackSeed, roundIndex, step, threshold,
		stake, totalStake)
	stepView = &StepView{
		Priority:       VrfComputePriority(sortitionValue, subUsers),
		SortitionProof: proof,
		SubUsers:       subUsers,
		ValidatorType:  validatorType,
		Threshold:      threshold,
	}

	sm.NewStepView(round, roundIndex, step, stepView)
	if subUsers > 0 {
		logging.Info("-----isValidator: YES.", "Round", round, "RoundIndex", roundIndex, "Kind", params.ValidatorKindToString(stepView.ValidatorType),
			"step", step, "Sub-Users", subUsers, "validatorTh", threshold,
			"stake", stake, "totalStake", totalStake, "seed", lookBackSeed.String()) //, "addr", sm.addr.String())

		//if step == UConStepProposal {
		//	// compute next round's seed and self's priority, then construct message and gossip
		//	stepView.SeedValue, stepView.SeedProof = ComputeSeed(sm.vrfSk, round, roundIndex, lookBackSeed)
		//}

		//todo metrics
		return true, stepView
	}

	logging.Info("-----isValidator: NO.", "Round", round, "RoundIndex", roundIndex, "Kind", params.ValidatorKindToString(stepView.ValidatorType),
		"Step", step, "Sub-Users", subUsers, "validatorTh", threshold,
		"stake", stake, "totalStake", totalStake, "seed", lookBackSeed.String()) //, "addr", sm.addr.String())
	return false, stepView
}
