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
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/youchainhq/go-youchain/bls"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/staking"
	"github.com/youchainhq/go-youchain/youdb"
)

type IsValidatorFn func(round *big.Int, roundIndex uint32, step uint32, lbType params.LookBackType) (bool, *StepView)

type BlockHashWithMaxPriorityFn func(round *big.Int, roundIndex uint32) (common.Hash, common.Hash, bool)

type OverThresholdFn func(voteType VoteType, count uint32) bool

type GetBlockInCacheFn func(blockHash common.Hash, priority common.Hash) *types.Block

type GetCurrentParamsFn func() *params.CaravelParams
type paramsManager interface {
	CurrentCaravelParams() *params.CaravelParams
	CertificateParams(round *big.Int) (*params.CaravelParams, error)
}

type VoteStatus struct {
	chamber map[VoteType]bool
	house   map[VoteType]bool
}

func (vs *VoteStatus) update(voteType VoteType, validatorType params.ValidatorKind) {
	if validatorType == params.KindChamber {
		if vs.chamber == nil {
			vs.chamber = make(map[VoteType]bool)
		}
		vs.chamber[voteType] = true
	} else if validatorType == params.KindHouse {
		if vs.house == nil {
			vs.house = make(map[VoteType]bool)
		}
		vs.house[voteType] = true
	}
}

func (vs *VoteStatus) status(voteType VoteType, validatorType params.ValidatorKind) bool {
	if validatorType == params.KindChamber && vs.chamber != nil {
		return vs.chamber[voteType]
	} else if validatorType == params.KindHouse && vs.house != nil {
		return vs.house[voteType]
	}

	return false
}

type Voter struct {
	lock            sync.Mutex
	round           *big.Int
	roundIndex      uint32
	step            uint32
	precommitted    bool
	committed       bool
	sentChangeEvent bool
	nextMarked      *MarkedBlockInfo
	curMarked       *MarkedBlockInfo
	//nextVoted       map[common.Hash]bool // avoid sending nextvote for a priority repeatedly
	nextVoted     *MarkedBlockInfo
	overPrevote   map[common.Hash]bool
	overPrecommit map[common.Hash]bool
	shouldCert    bool
	certificated  bool

	voteOver map[common.Hash]*VoteStatus

	votesMgr      *VotesWrapper
	votesWrappers *VotesWrapperList

	verifySortitionFn    VerifySortitionFn
	isValidatorFn        IsValidatorFn
	getMaxPriorityFn     BlockHashWithMaxPriorityFn
	blockInCacheFn       GetBlockInCacheFn
	getStakeFn           getStakeFn
	getValidatorsCountFn getValidatorsCountFn
	paramsMgr            paramsManager

	eventMux *event.TypeMux // send notifications
	eventSub *event.TypeMuxSubscription

	rawSk  *ecdsa.PrivateKey
	addr   common.Address
	blsMgr *VoteBLSMgr

	voteCache     *VoteDB
	votesUpdateEv *UpdateExistedHeaderEvent
}

func NewVoter(db youdb.Database,
	rawSk *ecdsa.PrivateKey,
	blsSk bls.SecretKey,
	eventMux *event.TypeMux,
	verifySortitionFn VerifySortitionFn,
	isValidatorFn IsValidatorFn,
	getHashFn BlockHashWithMaxPriorityFn,
	blockInCacheFn GetBlockInCacheFn,
	getStake getStakeFn,
	getValidatorsCount getValidatorsCountFn,
	pmgr paramsManager) *Voter {

	addr := crypto.PubkeyToAddress(rawSk.PublicKey)
	v := &Voter{
		rawSk: rawSk,
		addr:  addr,
		//votesMgr:             NewVotesWrapper(),
		votesWrappers:        NewVotesWrapperList(),
		verifySortitionFn:    verifySortitionFn,
		isValidatorFn:        isValidatorFn,
		getMaxPriorityFn:     getHashFn,
		blockInCacheFn:       blockInCacheFn,
		getStakeFn:           getStake,
		getValidatorsCountFn: getValidatorsCount,
		eventMux:             eventMux,
		voteCache:            NewVoteDB(db, rawSk),
		paramsMgr:            pmgr,
	}
	v.blsMgr = NewVoteBLSMgr(rawSk, blsSk)

	return v
}

func (v *Voter) Start(lbmgr LookBackMgr) {
	v.eventSub = v.eventMux.Subscribe(ContextChangeEvent{}, VoteMsgEvent{}) //, RoundIndexChangeEvent{})
	v.SetLookBackMgr(lbmgr)

	go v.eventLoop()
}

func (v *Voter) SetLookBackMgr(lbmgr LookBackMgr) {
	if nil != v.blsMgr {
		v.blsMgr.SetLookBackMgr(lbmgr)
	}
}

func (v *Voter) Stop() {
	v.eventSub.Unsubscribe()
	v.voteCache.Stop()
}

func (v *Voter) PackVotes(ev CommitEvent, backType params.LookBackType) (*UconValidators, error) {
	cp := v.paramsMgr.CurrentCaravelParams()
	if backType == params.LookBackCert {
		if ev.Round.Uint64()%params.ACoCHTFrequency != 0 {
			// not a certificate round, just return an empty object
			uv := &UconValidators{
				RoundIndex: ev.RoundIndex,
			}
			return uv, nil
		}

		p, err := v.paramsMgr.CertificateParams(ev.Round)
		if err != nil {
			return nil, fmt.Errorf("PackVotes get certificate params failed for round %v, originError: %v", v.round, err)
		}
		cp = p
	}

	if cp.EnableBls {
		return v.blsMgr.Verifier.PackVotes(ev, backType)
	} else {
		return NewUconValidators(ev, backType), nil
	}
}

func (v *Voter) updateContext(ev ContextChangeEvent) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.round == nil || v.round.Cmp(ev.Round) != 0 || v.roundIndex != ev.RoundIndex {
		if v.votesUpdateEv != nil {
			wrapper := v.votesWrappers.GetWrapper(v.votesUpdateEv.Round, v.votesUpdateEv.RoundIndex)
			if wrapper != nil {
				chamberPrecommits, _ := wrapper.getVotes(Precommit, v.votesUpdateEv.BlockHash, params.KindChamber)
				housePrecommits, _ := wrapper.getVotes(Precommit, v.votesUpdateEv.BlockHash, params.KindHouse)
				v.votesUpdateEv.ChamberPrecommits = chamberPrecommits
				v.votesUpdateEv.HousePrecommits = housePrecommits
				logging.Debug("UpdateExistedHeader Context.", "Round", v.votesUpdateEv.Round, "RI", v.votesUpdateEv.RoundIndex,
					"Block", v.votesUpdateEv.BlockHash.String(), "Chamber", len(v.votesUpdateEv.ChamberPrecommits), "House", len(v.votesUpdateEv.HousePrecommits))
				v.eventMux.AsyncPost(*v.votesUpdateEv)
			}

			v.votesUpdateEv = nil
		}

		//v.votesMgr.clearVotesInfo(ev.Round, ev.RoundIndex)
		v.votesWrappers.NewWrapper(ev.Round, ev.RoundIndex)
		v.votesMgr = v.votesWrappers.GetWrapper(ev.Round, ev.RoundIndex)

		v.precommitted = false
		v.committed = false
		v.sentChangeEvent = false
		v.certificated = false

		if ev.RoundIndex == 1 {
			v.curMarked = nil
		} else {
			v.curMarked = v.nextVoted
		}
		v.nextMarked = nil
		v.nextVoted = nil
		v.voteOver = make(map[common.Hash]*VoteStatus)
		//v.overPrevote = make(map[common.Hash]bool)
		//v.overPrecommit = make(map[common.Hash]bool)
		//v.nextVoted = make(map[common.Hash]bool)
	}
	if v.round == nil || v.round.Cmp(ev.Round) != 0 {
		v.blsMgr.update(ev.Round, ev.Certificate)
	}

	v.round = ev.Round
	v.roundIndex = ev.RoundIndex
	v.step = ev.Step
	v.shouldCert = ev.Certificate

	v.voteCache.UpdateContext(v.round, v.roundIndex)

	switch v.step {
	case UConStepPrevote:
		if v.curMarked != nil && CompareCommonHash(v.curMarked.BlockHash, common.Hash{}) > 0 {
			v.vote(Prevote, v.curMarked.BlockHash, v.curMarked.Priority)
		} else {
			// gossip the prevote message when this node is a verifier in this step
			// get the block hash with the max priority
			priority, blockHash, exist := v.getMaxPriorityFn(v.round, v.roundIndex)
			if !exist {
				logging.Error("NoMaxPriority.", "Round", v.round, "RoundIndex", v.roundIndex)
				return
			}
			logging.Debug("MaxPriority.", "Round", v.round, "RoundIndex", v.roundIndex, "Hash", blockHash.String(), "Priority", priority.String())
			v.vote(Prevote, blockHash, priority)
		}

	case UConStepPrecommit:
		fallthrough
	case UConStepCertificate:
		// send next-round-index message
		if v.committed || v.sentChangeEvent {
			return
		}
		if v.nextMarked == nil {
			v.setMarkedBlock(common.Hash{}, common.Hash{})
		} else {
			v.setMarkedBlock(v.nextMarked.BlockHash, v.nextMarked.Priority)
		}
	}
}

func (v *Voter) judgeVoteCount(voteType VoteType, count uint32, threshold uint64, blockHash common.Hash, priority common.Hash, validatorType params.ValidatorKind) {
	r := OverThreshold(count, threshold, voteType != Certificate)
	if !r || (v.committed && voteType != Precommit) {
		return
	}

	// should update the precommit votes
	if v.committed && voteType == Precommit {
		v.votesUpdateEv = &UpdateExistedHeaderEvent{
			Round:      v.round,
			RoundIndex: v.roundIndex,
			BlockHash:  blockHash,
		}
		return
	}

	logging.Info("VoteOverCount.", "Round", v.round, "RoundIndex", v.roundIndex, VoteTypeToString(voteType), params.ValidatorKindToString(validatorType), "Count", count, "Threshold", threshold, "block", blockHash.String())

	if v.voteOver[blockHash] == nil {
		v.voteOver[blockHash] = &VoteStatus{}
	}
	voteStatus := v.voteOver[blockHash]
	voteStatus.update(voteType, validatorType)

	//// check the votes of other kind validators
	//oppositeKind := OppositeValidatorType(validatorType)
	//if voteType != Certificate && v.getValidatorsCountFn(v.round, oppositeKind, params.LookBackStake) > 0 && !voteStatus.status(voteType, oppositeKind) {
	//	return
	//}
	if validatorType != params.KindChamber {
		return
	}

	switch voteType {
	case Prevote:
		if !v.precommitted {
			err := v.vote(Precommit, blockHash, priority)
			if err == nil {
				v.precommitted = true
			}

			v.setMarkedBlock(blockHash, priority)
		}

	case Precommit:
		if !v.shouldCert {
			v.commit(blockHash, priority)
			v.setMarkedBlock(blockHash, priority)
		} else {
			if !v.certificated {
				err := v.vote(Certificate, blockHash, priority)
				if err == nil {
					v.certificated = true
				}
			} else if voteStatus.status(Certificate, params.KindChamber) {
				v.commit(blockHash, priority)
				v.setMarkedBlock(blockHash, priority)
			}
		}

	case Certificate:
		if voteStatus.status(Precommit, params.KindChamber) {
			//hc := v.getValidatorsCountFn(v.round, params.KindHouse, params.LookBackStake)
			//if hc <= 0 || (hc > 0 && voteStatus.status(Precommit, params.KindHouse)) {
			v.commit(blockHash, priority)
			v.setMarkedBlock(blockHash, priority)
			//}
		}

	case NextIndex:
		// change to next round-index
		if v.sentChangeEvent {
			return
		}

		//if (v.shouldCert && v.step < UConStepCertificate) || (!v.shouldCert && v.step < UConStepPrecommit) {
		//	return
		//}
		//v.setMarkedBlock(blockHash, priority)

		v.eventMux.AsyncPost(RoundIndexChangeEvent{
			Round:      v.round,
			RoundIndex: v.roundIndex,
			BlockHash:  blockHash,
			Priority:   priority,
		})
		v.sentChangeEvent = true
		logging.Info("RoundIndexChangeEvent.", "Round", v.round, "RoundIndex", v.roundIndex, "Block", blockHash.String(), "Priority", priority.String())
	}
}

func (v *Voter) eventLoop() {
	for obj := range v.eventSub.Chan() {
		if obj == nil {
			return
		}
		switch ev := obj.Data.(type) {
		case ContextChangeEvent:
			v.updateContext(ev)
		case VoteMsgEvent:
			v.processVoteMsg(ev, msgSame)
			//case RoundIndexChangeEvent:
			//	v.resetMarkedBlock()
		}
	}
}

func (v *Voter) vote(voteType VoteType, blockHash common.Hash, priority common.Hash) error {
	logging.Debug("vote.", "voteType", voteType, "block", blockHash.String(), "priority", priority.String())
	lbType := params.LookBackPos
	if voteType == Certificate {
		lbType = params.LookBackCert
	}
	isValidator, stepView := v.isValidatorFn(v.round, v.roundIndex, uint32(voteType), lbType)
	if !isValidator || stepView == nil {
		return fmt.Errorf("not a validator")
	}

	if voteType == NextIndex && v.nextVoted != nil && v.voteCache.ExistVoteData(voteType, v.round, v.roundIndex) { //v.nextVoted[priority] {
		return fmt.Errorf("already voted.")
	}

	// need to append signature
	voteInfo, err := v.signVote(voteType, blockHash, stepView)
	if err != nil {
		return err
	}

	msg := &BlockHashWithVotes{
		Priority:   priority,
		BlockHash:  blockHash,
		Round:      v.round,
		RoundIndex: v.roundIndex,
		Vote:       voteInfo,
		Timestamp:  uint64(time.Now().Unix()),
	}

	ecp, err := Encode(msg)
	if err != nil {
		logging.Error("encode BlockHashWithVotes message failed: ", msg, err)
		return err
	}

	err = v.voteCache.UpdateVoteData(voteType, v.round, v.roundIndex)
	if err != nil {
		logging.Error("UpdateVoteDataCache failed.", "err", err)
		return err
	}

	// update statistics
	_, count := v.votesMgr.newVote(v.round, v.roundIndex, voteType, v.addr, priority, blockHash, voteInfo, stepView.ValidatorType)

	v.eventMux.AsyncPost(SendMessageEvent{Code: VoteTypeToMsgCode(voteType), Payload: ecp, Round: v.round})

	//todo metrics

	// should compare the votes count with threshold
	v.judgeVoteCount(voteType, count, stepView.Threshold, msg.BlockHash, msg.Priority, stepView.ValidatorType)

	logging.Info("SelfVote.", "Round", msg.Round, "RoundIndex", msg.RoundIndex, VoteTypeToString(voteType), params.ValidatorKindToString(stepView.ValidatorType),
		"Sub-Users", msg.Vote.Votes, "TotalCount", count, "Threshold", stepView.Threshold, "addr", v.addr.String(), "hash", msg.BlockHash.String())

	return nil
}

func (v *Voter) signVote(voteType VoteType, blockHash common.Hash, stepView *StepView) (*SingleVote, error) {
	voteInfo := &SingleVote{
		Votes: stepView.SubUsers,
		Proof: stepView.SortitionProof,
	}

	payload := append(blockHash.Bytes(), append(v.round.Bytes(), uint32ToBytes(v.roundIndex)...)...)

	// for certificate vote, use the parameters on the certLookBack header
	cp := v.paramsMgr.CurrentCaravelParams()
	if voteType == Certificate {
		p, err := v.paramsMgr.CertificateParams(v.round)
		if err != nil {
			return nil, fmt.Errorf("signVote get certificate params failed for round %v, originError: %v", v.round, err)
		}
		cp = p
	}

	if cp.EnableBls {
		err := v.blsMgr.SignVote(voteType, voteInfo, payload)
		if err != nil {
			return nil, err
		}
	} else {
		// need to append signature
		signature, err := Sign(v.rawSk, payload)
		if err != nil {
			return nil, err
		}
		voteInfo.Signature = signature
	}
	return voteInfo, nil
}

func (v *Voter) getAddrFromVote(voteType VoteType, blockHash common.Hash, vote *SingleVote, round *big.Int, roundIndex uint32) (vrfpk *ecdsa.PublicKey, addr common.Address, err error) {
	payload := append(blockHash.Bytes(), append(round.Bytes(), uint32ToBytes(roundIndex)...)...) ////append(blockHash.Bytes(), uint32ToBytes(vote.Votes)...)
	// for certificate vote, use the parameters on the certLookBack header
	cp := v.paramsMgr.CurrentCaravelParams()
	if voteType == Certificate {
		p, err := v.paramsMgr.CertificateParams(round)
		if err != nil {
			return nil, common.Address{}, fmt.Errorf("getAddrFromVote: get certificate params failed for round %v, originError: %v", round, err)
		}
		cp = p
	}
	if cp.EnableBls {
		vrfpk, err = v.blsMgr.getAddrFromVote(voteType, round, payload, vote)
	} else {
		vrfpk, err = GetSignaturePublicKey(payload, vote.Signature)
	}
	if err != nil {
		return nil, common.Address{}, err
	}
	addr = crypto.PubkeyToAddress(*vrfpk)
	return vrfpk, addr, nil
}

func (v *Voter) RecoverSignerInfo(vs *state.Validators, vote *SingleVote) (signer *state.Validator, pk bls.PublicKey, vrfpk *ecdsa.PublicKey, err error) {
	return v.blsMgr.RecoverSignerInfo(vs, vote)
}

func (v *Voter) processVoteMsg(ev VoteMsgEvent, status MsgReceivedStatus) (error, bool) {
	v.lock.Lock()
	defer v.lock.Unlock()

	votesmsg, voteType := ev.Msg, ev.VType
	msg := votesmsg.VotesData
	if status == msgSame {
		if msg.Vote == nil {
			return fmt.Errorf("vote info is empty"), true
		} else if msg.Round.Cmp(v.round) != 0 || msg.RoundIndex != v.roundIndex {
			return nil, false
		}
	}
	vote := msg.Vote

	pubKey, addr, err := v.getAddrFromVote(voteType, msg.BlockHash, msg.Vote, msg.Round, msg.RoundIndex)
	if err != nil {
		logging.Error("verify vote failed", "err", err)
		return err, true
	}
	if addr != ev.Msg.addr {
		err := fmt.Errorf("sender's address doesn't match the vote's address")
		logging.Error("verify vote failed", "err", err)
		return err, true
	}
	// check whether have stored this Vote information before
	lbType := params.LookBackPos
	if voteType == Certificate {
		lbType = params.LookBackCert
	}
	_, _, threshold, validatorType, _, err := v.getStakeFn(msg.Round, addr, false, lbType)
	if err != nil {
		return err, true
	}
	// verify sortition
	data := &SortitionData{
		Round:      msg.Round,
		RoundIndex: msg.RoundIndex,
		Step:       uint32(voteType),
		Proof:      vote.Proof,
		Votes:      vote.Votes,
	}
	err = v.verifySortitionFn(pubKey, data, lbType)
	if err != nil {
		logging.Error("verifyPriority msgPriorityProposal failed", "err", err)
		return err, true
	}

	if status == msgFuture || status == msgInvalid {
		return nil, false
	}

	wrapper := v.votesWrappers.GetWrapper(msg.Round, msg.RoundIndex)
	if (status == msgOldRound || status == msgOldRoundIndex) && (wrapper == nil || voteType != Precommit) {
		return nil, false
	}
	if wrapper == nil && status == msgSame {
		wrapper = v.votesWrappers.NewWrapper(msg.Round, msg.RoundIndex)
		v.votesMgr = wrapper
	}

	result, voteInfoData := wrapper.addrVoteInfo(msg.Round, msg.RoundIndex, voteType, addr, msg.BlockHash, validatorType)
	switch result {
	case addrNotVoted:
		// store the Vote information
		voteInfo := &SingleVote{
			VoterIdx:  vote.VoterIdx,
			Votes:     vote.Votes,
			Signature: vote.Signature,
			Proof:     vote.Proof,
		}
		add, totalCount := wrapper.newVote(msg.Round, msg.RoundIndex, voteType, addr, msg.Priority, msg.BlockHash, voteInfo, validatorType)
		if add {
			logging.Info("ParseVote.", "Round", msg.Round, "RoundIndex", msg.RoundIndex, VoteTypeToString(voteType), params.ValidatorKindToString(validatorType),
				"Sub-Users", vote.Votes, "TotalCount", totalCount, "Threshold", threshold, "addr", addr.String(), "hash", msg.BlockHash.String())

			// should compare the votes count with threshold
			if status == msgSame {
				v.judgeVoteCount(voteType, totalCount, threshold, msg.BlockHash, msg.Priority, validatorType)
			} else if OverThreshold(totalCount, threshold, false) {
				// msgOld, should update the block header
				chamberPrecommits, _ := wrapper.getVotes(Precommit, msg.BlockHash, params.KindChamber)
				housePrecommits, _ := wrapper.getVotes(Precommit, msg.BlockHash, params.KindHouse)
				updateEv := UpdateExistedHeaderEvent{
					Round:             msg.Round,
					RoundIndex:        msg.RoundIndex,
					BlockHash:         msg.BlockHash,
					ChamberPrecommits: chamberPrecommits,
					HousePrecommits:   housePrecommits,
				}
				logging.Debug("UpdateExistedHeader Over.", "Round", updateEv.Round, "RI", updateEv.RoundIndex,
					"Block", updateEv.BlockHash.String(), "Chamber", len(updateEv.ChamberPrecommits), "House", len(updateEv.HousePrecommits))
				v.eventMux.AsyncPost(updateEv)
			}
		}

	case addrVoteExist:
		return nil, false

	case addrDifferentVote:
		if voteInfoData == nil || voteType == NextIndex {
			return nil, false
		}

		logging.Error("DoubleVote.", "Round", msg.Round, "RoundIndex", msg.RoundIndex, VoteTypeToString(voteType), params.ValidatorKindToString(validatorType),
			"Addr", addr.String(), "Hash1", voteInfoData.Hash.String(), "Hash2", msg.BlockHash.String())

		// detect malicious voting
		signs := make(map[common.Hash][]byte)
		signs[voteInfoData.Hash] = voteInfoData.Signature
		signs[msg.BlockHash] = msg.Vote.Signature
		evData := staking.EvidenceDoubleSign{
			Round:      msg.Round,
			RoundIndex: msg.RoundIndex,
			Signs:      signs,
		}
		ev := staking.NewEvidence(evData)
		v.eventMux.AsyncPost(ev)
		return nil, false

	case addrDoubleVoted:
		return nil, false
	}

	return nil, false
}

func (v *Voter) setMarkedBlock(blockHash, priority common.Hash) { //, vote bool) { //, voteType VoteType) {
	emptyHash := common.Hash{}
	if v.nextVoted != nil &&
		(CompareCommonHash(v.nextVoted.BlockHash, emptyHash) > 0 || CompareCommonHash(v.nextVoted.BlockHash, blockHash) == 0 || CompareCommonHash(blockHash, emptyHash) == 0) {
		// already voted
		return
	}

	block := v.blockInCacheFn(blockHash, priority)
	if block == nil && CompareCommonHash(blockHash, emptyHash) > 0 {
		return
	}

	blockInfo := &MarkedBlockInfo{
		Priority:   priority,
		BlockHash:  blockHash,
		Round:      v.round,
		RoundIndex: v.roundIndex,
		Block:      block,
	}

	if v.step < UConStepPrecommit {
		if v.nextMarked == nil && CompareCommonHash(blockHash, emptyHash) > 0 {
			v.nextMarked = blockInfo
		}
		return
	}

	//if v.nextMarked == nil || CompareCommonHash(v.nextMarked.Priority, common.Hash{}) == 0 {
	//v.nextMarked = blockInfo

	//step := UConStepPrecommit
	//if v.shouldCert {
	//	step = UConStepCertificate
	//}
	//if v.step >= uint32(step) || v.committed {
	err := v.vote(NextIndex, blockHash, priority)
	if err != nil {
		v.nextVoted = blockInfo
		//v.nextMarked = blockInfo
		logging.Info("setMarkedBlock.", "Round", v.round, "RoundIndex", v.roundIndex, "Hash", blockHash.String())
	}
	//}
	//}
}

func (v *Voter) getMarkedBlock(round *big.Int, roundIndex uint32) *MarkedBlockInfo {
	return v.nextVoted //v.nextMarked
}

func (v *Voter) removeMarkedBlock(blockHash common.Hash) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if CompareCommonHash(v.nextMarked.BlockHash, blockHash) == 0 {
		v.nextMarked = nil
		v.nextVoted = nil
	}
}

func (v *Voter) commit(blockHash, priority common.Hash) {
	logging.Info("commit.", "Round", v.round, "RoundIndex", v.roundIndex, "block", blockHash.String(), "priority", priority.String())
	block := v.blockInCacheFn(blockHash, priority)
	if block == nil {
		return
	}
	v.committed = true
	// commit
	chamberPrecommits, _ := v.votesMgr.getVotes(Precommit, blockHash, params.KindChamber)
	housePrecommits, _ := v.votesMgr.getVotes(Precommit, blockHash, params.KindHouse)
	ev := CommitEvent{
		Round:             v.round,
		RoundIndex:        v.roundIndex,
		Block:             block,
		ChamberPrecommits: chamberPrecommits,
		HousePrecommits:   housePrecommits,
	}

	if v.shouldCert {
		chamberCerts, count := v.votesMgr.getVotes(Certificate, blockHash, params.KindChamber)
		ev.ChamberCerts = chamberCerts
		logging.Debug("Certificate votes.", "Round", v.round, "RoundIndex", v.roundIndex, "count", count)
	}

	v.eventMux.AsyncPost(ev)

	logging.Debug("send CommitEvent.", "Round", v.round, "RoundIndex", v.roundIndex, "block", blockHash.String())
}

func (v *Voter) existHashOverVotesThreshold(round *big.Int, roundIndex uint32, chamberTh, houseTh uint32) bool {
	if v.votesMgr != nil {
		return v.votesMgr.existHashOverVotesThreshold(round, roundIndex, chamberTh, houseTh)
	}
	return false
}

func OverThreshold(count uint32, threshold uint64, isPos bool) bool {
	th := ValidatorProportionThreshold
	if !isPos {
		th = CertValProportionThreshold
	}
	if count >= uint32(float64(threshold)*th) {
		return true
	}

	return false
}

func OppositeValidatorType(kind params.ValidatorKind) params.ValidatorKind {
	if kind == params.KindChamber {
		return params.KindHouse
	} else if kind == params.KindHouse {
		return params.KindChamber
	}
	return params.KindValidator
}
