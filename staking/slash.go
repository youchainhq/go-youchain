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

package staking

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
)

type hashSignPair struct {
	Hash common.Hash
	Sign []byte
}

//processedEvidencesResult  result package
type processedEvidencesResult struct {
	pendingEvidences   []Evidence
	confirmedEvidences []Evidence
	deletedEvidences   []Evidence
	affectedValidators []*common.Address
}

//replaySlashing  replay evidences in block
func (s *Staking) replaySlashing(ctx *context) ([]Evidence, []Evidence, []*common.Address, error) {
	header := ctx.header
	if len(header.SlashData) == 0 {
		return nil, nil, nil, nil
	}
	log.Debug("replaySlashing", "header", header.Number, "hash", header.Root.String(), "slashdata", hexutil.Encode(header.SlashData))

	var evidences []Evidence
	if err := rlp.DecodeBytes(header.SlashData, &evidences); err != nil {
		return nil, nil, nil, err
	}

	if len(evidences) == 0 {
		return nil, nil, nil, fmt.Errorf("empty evidences of number: %d", header.Number)
	}

	parentHeight := new(big.Int).Set(ctx.chain.CurrentHeader().Number)

	var verifiedEvidences []Evidence
	for _, evidence := range evidences {
		switch evidence.Type {
		case EvidenceTypeInactive:
			var inactive EvidenceInactive
			if data := evidence.data.Load(); data != nil {
				inactive = data.(EvidenceInactive)
			} else {
				if err := rlp.DecodeBytes(evidence.Data, &inactive); err != nil {
					continue
				}
				evidence.data.Store(inactive)
			}

			addresses := s.votesWatcher.Inactive(inactive.Round, s.inactiveCheckingRange())
			var inputs []string
			for _, v := range inactive.Validators {
				inputs = append(inputs, v.String())
			}
			var output []string
			for _, v := range addresses {
				output = append(output, v.String())
			}
			log.Trace("check replay inactive", "height", header.Number, "height", inactive.Round, "input", strings.Join(inputs, ","), "output", strings.Join(output, ","))
			if !cmpSet(inputs, output) {
				continue // discard
			}
		}
		verifiedEvidences = append(verifiedEvidences, evidence)
	}

	confirmedEvidences, pendingEvidences, affectedValidators := s.processEvidences(ctx.config, ctx.db, header, parentHeight, ctx.receipt, evidences)
	return confirmedEvidences, pendingEvidences, affectedValidators, nil
}

func cmpSet(a []string, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i, v := range b {
		if a[i] != v {
			return false
		}
	}
	return true
}

//slashing evidences
func (s *Staking) slashing(ctx *context) ([]Evidence, []Evidence, []*common.Address, error) {
	log.Trace("slashing start", "height", ctx.header.Number, "count", len(s.evidences))
	proc := time.Now()
	var confirm, pending, affected int
	defer func() {
		log.Trace("slashing finished", "height", ctx.header.Number, "miner", ctx.header.Coinbase.String(), "confirm", confirm, "pending", pending, "affected", affected, "elapsed", time.Since(proc))
	}()

	if len(s.evidences) == 0 {
		return nil, nil, nil, nil
	}

	// protect staking.evidences
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var evidences = make([]Evidence, len(s.evidences))
	copy(evidences, s.evidences)
	parentHeight := s.blockChain.CurrentHeader().Number //check parent block
	confirmedEvidences, pendingEvidences, affectedValidators := s.processEvidences(ctx.config, ctx.db, ctx.header, parentHeight, ctx.receipt, evidences)
	s.evidences = pendingEvidences
	affected = len(affectedValidators)
	pending = len(pendingEvidences)
	confirm = len(confirmedEvidences)
	var (
		slashData []byte
		err       error
	)

	if len(confirmedEvidences) > 0 {
		if slashData, err = rlp.EncodeToBytes(confirmedEvidences); err == nil {
			log.Debug("slash data", "num", ctx.header.Number.Uint64(), "data", hexutil.Encode(slashData))
			ctx.header.SlashData = slashData
		} else {
			log.Warn("slashing encode data failed", "err", err)
		}
	}

	return confirmedEvidences, pendingEvidences, affectedValidators, nil
}

//processEvidences .
func (s *Staking) processEvidences(config *params.YouParams, currentDB *state.StateDB, header *types.Header, parentHeight *big.Int, receipt *types.Receipt, evidences []Evidence) ([]Evidence, []Evidence, []*common.Address) {
	var processResult = &processedEvidencesResult{}

	log.Debug("processEvidences", "height", header.Number, "evidences", len(evidences))
	doubleSignedValidators := make(map[common.Address]struct{})
	for _, evidence := range evidences {
		switch evidence.Type {
		case EvidenceTypeDoubleSignV5:
			s.processDoubleSignV5(config, currentDB, header, parentHeight.Uint64(), evidence, receipt, processResult, doubleSignedValidators)
		default:
			log.Warn("ignored unknown evidence type", "type", evidence.Type)

			// Currently only EvidenceTypeDoubleSignV5 will take effects. (2020-12-15)

			//case EvidenceTypeDoubleSign:
			//	s.processDoubleSign(config, currentDB, header, parentHeight, evidence, receipt, processResult, doubleSignedValidators)
			//
			//case EvidenceTypeInactive:
			//	s.processInactive(config, currentDB, header, parentHeight, evidence, receipt, processResult)
		}
	}
	log.Debug("processEvidencesResult", "height", header.Number, "confirmed", len(processResult.confirmedEvidences), "pending", len(processResult.pendingEvidences), "affected", len(processResult.affectedValidators))
	return processResult.confirmedEvidences, processResult.pendingEvidences, processResult.affectedValidators
}

func (s *Staking) processInactive(config *params.YouParams, currentDB *state.StateDB, header *types.Header, parentHeight *big.Int, evidence Evidence, receipt *types.Receipt, processResult *processedEvidencesResult) {
	var inactive EvidenceInactive

	if data := evidence.data.Load(); data != nil {
		inactive = data.(EvidenceInactive)
	} else {
		if err := rlp.DecodeBytes(evidence.Data, &inactive); err != nil {
			return
		}
		evidence.data.Store(inactive)
	}

	if len(inactive.Validators) == 0 {
		return
	}

	if parentHeight.Uint64() > inactive.Round {
		log.Trace("drop old evidence", "parent", parentHeight, "height", header.Number, "eround", inactive.Round)
		return
	}

	if parentHeight.Uint64() < inactive.Round {
		processResult.pendingEvidences = append(processResult.pendingEvidences, evidence)
		return
	}

	var (
		skippedNil     int
		skippedOffline int
		skippedCd      int
		affected       int
	)
	for _, addr := range inactive.Validators {
		val := currentDB.GetValidatorByMainAddr(addr)
		if val == nil {
			log.Warn("validator not found", "add", addr.String())
			skippedNil++
			continue
		}
		if val.Status != params.ValidatorOnline {
			skippedOffline++
			continue
		}
		if val.LastInactive+s.inactiveCheckingRange() > header.Number.Uint64() {
			skippedCd++
			continue
		}

		penaltyAmount := new(big.Int).Div(new(big.Int).Mul(val.Token, new(big.Int).SetUint64(config.PenaltyFractionForInactive)), big.NewInt(100))
		totalPenalty, affectedRecords, _ := doPenalize(config, EvidenceTypeInactive, currentDB, header, val, penaltyAmount, inactive.Round)

		// penalty
		if totalPenalty.Cmp(bigZero) > 0 {
			affected++
			processResult.affectedValidators = append(processResult.affectedValidators, &addr)
			if slashLogData, err := NewSlashData(EventTypeInactive, val.MainAddress(), totalPenalty, affectedRecords, &evidence); err == nil {
				receipt.Logs = append(receipt.Logs, &types.Log{
					Address:     params.StakingModuleAddress,
					Topics:      []common.Hash{common.StringToHash(LogTopicSlashing)},
					Data:        newLogData(LogTopicSlashing, []string{val.MainAddress().String(), slashLogData.Hash().String()}, slashLogData).EncodeToBytes(),
					BlockNumber: header.Number.Uint64(),
				})
			} else {
				log.Error("create slashLogData failed", "height", header.Number, "err", err)
			}
		}
	}
	log.Debug("processInactive", "height", header.Number,
		"inactive", len(inactive.Validators),
		"totalAffected", len(processResult.affectedValidators),
		"cd", skippedCd,
		"offline", skippedOffline,
		"nil", skippedNil,
		"logs", len(receipt.Logs), "affected", affected)
	//ignore useless evidence
	if affected > 0 {
		processResult.confirmedEvidences = append(processResult.confirmedEvidences, evidence)
	} else {
		processResult.deletedEvidences = append(processResult.deletedEvidences, evidence)
	}
	return
}

func (s *Staking) processDoubleSign(config *params.YouParams, currentDB *state.StateDB, header *types.Header, parentHeight *big.Int, evidence Evidence, receipt *types.Receipt, result *processedEvidencesResult, doubleSignedValidators map[common.Address]struct{}) {
	var doubleSign EvidenceDoubleSign
	if err := rlp.DecodeBytes(evidence.Data, &doubleSign); err != nil {
		return
	}

	if len(doubleSign.Signs) < 2 {
		return
	}

	var hashPairs []hashSignPair
	for hash, sign := range doubleSign.Signs {
		hashPairs = append(hashPairs, hashSignPair{Hash: hash, Sign: sign})
	}

	log.Debug("slashing", "type", EvidenceTypeDoubleSign, "parent", parentHeight, "eRound", doubleSign.Round, "eRoundIndex", doubleSign.RoundIndex, "signs", len(doubleSign.Signs))
	switch doubleSign.Round.Cmp(parentHeight) {
	case 0:
		var signerAddr common.Address
		if addr := evidence.addr.Load(); addr != nil {
			signerAddr = addr.(common.Address)
		} else {
			signerAddr = exportDoubleSigner(doubleSign, hashPairs)
			evidence.addr.Store(signerAddr)
		}

		if signerAddr == (common.Address{}) {
			return
		}

		if _, ok := doubleSignedValidators[signerAddr]; ok {
			return
		}

		val := currentDB.GetValidatorByMainAddr(signerAddr)
		if val == nil {
			return
		}

		doubleSignedValidators[signerAddr] = struct{}{}

		penaltyAmount := new(big.Int).Div(new(big.Int).Mul(val.Token, new(big.Int).SetUint64(config.PenaltyFractionForDoubleSign)), big.NewInt(100))
		totalPenalty, affectedRecords, _ := doPenalize(config, EvidenceTypeDoubleSign, currentDB, header, val, penaltyAmount, doubleSign.Round.Uint64())

		var affected int
		// penalty
		if totalPenalty.Cmp(bigZero) > 0 {
			affected++
			result.affectedValidators = append(result.affectedValidators, &signerAddr)
			if slashLogData, err := NewSlashData(EventTypeDoubleSign, val.MainAddress(), totalPenalty, affectedRecords, &evidence); err == nil {
				receipt.Logs = append(receipt.Logs, &types.Log{
					Address:     params.StakingModuleAddress,
					Topics:      []common.Hash{common.StringToHash(LogTopicSlashing)},
					Data:        newLogData(LogTopicSlashing, []string{val.MainAddress().String(), slashLogData.Hash().String()}, slashLogData).EncodeToBytes(),
					BlockNumber: header.Number.Uint64(),
				})
			}
		}

		if affected > 0 {
			result.confirmedEvidences = append(result.confirmedEvidences, evidence)
		} else {
			result.deletedEvidences = append(result.deletedEvidences, evidence)
		}

	case 1:
		result.pendingEvidences = append(result.pendingEvidences, evidence) // future evidences

	case -1:
		if parentHeight.Uint64()-doubleSign.Round.Uint64() <= config.MaxEvidenceExpiredIn {
			result.pendingEvidences = append(result.pendingEvidences, evidence)
		} else {
			log.Warn("evidence expired", "round", doubleSign.Round, "roundIndex", doubleSign.RoundIndex) // discard expired evidences
		}
	}
}

func doPenalize(config *params.YouParams, typ string, currentDB *state.StateDB, header *types.Header, val *state.Validator, penaltyAmount *big.Int, happenedRound uint64) (totalPenalty *big.Int, affectedRecords []*SlashWithdrawRecord, pRecords []*PenaltyRecord) {
	var newVal *state.Validator
	if penaltyAmount.Sign() > 0 {
		newVal, totalPenalty, affectedRecords, pRecords = takePenalty(currentDB, val, penaltyAmount)
	} else {
		newVal, totalPenalty = val.PartialCopy(), penaltyAmount
	}
	newVal.Status = params.ValidatorOffline
	newVal.Expelled = true
	var expelExpired uint64
	switch typ {
	case EvidenceTypeDoubleSign:
		fallthrough
	case EvidenceTypeDoubleSignV5:
		expelExpired = header.Number.Uint64() + config.ExpelledRoundForDoubleSign
	case EvidenceTypeInactive:
		expelExpired = header.Number.Uint64() + config.ExpelledRoundForInactive
		newVal.LastInactive = header.Number.Uint64()
	}
	if expelExpired > newVal.ExpelExpired {
		newVal.ExpelExpired = expelExpired
	}

	updated := currentDB.UpdateValidator(newVal, val)
	success := currentDB.ValidatorsModified()
	currentDB.AddBalance(config.PenaltyTo, totalPenalty)
	log.Debug("doPenalize", "height", header.Number, "happened", happenedRound, "type", typ, "val", val.MainAddress().String(), "status", val.Status, "updated", updated,
		"token", newVal.Token, "stake", newVal.Stake,
		"penalty", totalPenalty, "affected", len(affectedRecords),
		"l1", val.LastInactive, "l2", newVal.LastInactive, "success", success)
	return
}

func takePenalty(currentDB *state.StateDB, val *state.Validator, penaltyAmount *big.Int) (newVal *state.Validator, totalPenalty *big.Int, affectedRecords []*SlashWithdrawRecord, pRecords []*PenaltyRecord) {
	totalPenalty = new(big.Int)
	// distribute penalty to each involved account
	// for validator itself, should calc the risk obligation
	obligation := new(big.Int)
	currTotal := new(big.Int).Set(penaltyAmount)
	if val.RiskObligation > 0 && val.RiskObligation <= params.CommissionRateBase {
		obligation.Mul(currTotal, big.NewInt(int64(val.RiskObligation)))
		obligation.Div(obligation, big.NewInt(int64(params.CommissionRateBase)))
		currTotal.Sub(currTotal, obligation)
	}
	per, rem := new(big.Int).QuoRem(currTotal, val.Stake, new(big.Int))
	selfPenalty := new(big.Int).Mul(per, val.SelfStake)
	selfPenalty.Add(selfPenalty, rem)
	selfPenalty.Add(selfPenalty, obligation)
	dlgPenalty := make(map[common.Address]*big.Int)
	for _, d := range val.Delegations {
		dlgPenalty[d.Delegator] = new(big.Int).Mul(per, d.Stake)
	}

	// common function
	setActual := func(source, target, actual *big.Int) {
		if source.Cmp(target) >= 0 {
			actual.Set(target)
		} else {
			actual.Set(source)
		}
	}

	updateCounter := func(amount *big.Int, val *state.Validator, sourceToken, sourceStake *big.Int) {
		totalPenalty.Add(totalPenalty, amount)
		penaltyAmount.Sub(penaltyAmount, amount)
		if val != nil {
			newToken := new(big.Int).Sub(sourceToken, amount)
			newStake := params.YOUToStake(newToken)
			delta := new(big.Int).Sub(sourceStake, newStake)
			sourceToken.Set(newToken)
			sourceStake.Set(newStake)
			val.Token.Sub(val.Token, amount)
			val.Stake.Sub(val.Stake, delta)
		}
	}

	// first take penalty from withdraw
	withdrawQueue := currentDB.GetWithdrawQueue()
	affectedRecords = []*SlashWithdrawRecord{}

	fromWithdraw := new(big.Int) // for reuse
	for _, record := range withdrawQueue.Records {
		if penaltyAmount.Cmp(bigZero) <= 0 {
			break
		}
		if record.Validator != val.MainAddress() || record.Finished != 0 {
			continue
		}

		var rest *big.Int
		if record.Delegator != (common.Address{}) {
			rest = dlgPenalty[record.Delegator]
		} else {
			rest = selfPenalty
		}
		if rest == nil || rest.Sign() <= 0 {
			continue
		}

		setActual(record.FinalBalance, rest, fromWithdraw)
		if fromWithdraw.Sign() > 0 {
			record.FinalBalance.Sub(record.FinalBalance, fromWithdraw)
			updateCounter(fromWithdraw, nil, nil, nil)
			rest.Sub(rest, fromWithdraw) // this will surely change the original map value, because this is a reference

			slashRecord := SlashWithdrawRecord{
				Token:  fromWithdraw,
				Record: record.DeepCopy(), //save modified record as slash result
			}
			affectedRecords = append(affectedRecords, &slashRecord)
		}
	}

	// second, take penalty from staking
	newVal = val.PartialCopy()
	fromDeposit := fromWithdraw // just for clear
	if penaltyAmount.Sign() > 0 {
		if selfPenalty.Sign() > 0 {
			setActual(val.SelfToken, selfPenalty, fromDeposit)
			if fromDeposit.Sign() > 0 {
				updateCounter(fromDeposit, newVal, newVal.SelfToken, newVal.SelfStake)
				pRecords = append(pRecords, &PenaltyRecord{
					Address: val.MainAddress(),
					Amount:  new(big.Int).Set(fromDeposit),
				})
			}
		}

		var rest *big.Int
		updatedDFrom := make([]*state.DelegationFrom, 0, newVal.Delegations.Len())
		for _, d := range newVal.Delegations {
			if penaltyAmount.Sign() <= 0 {
				break
			}
			rest = dlgPenalty[d.Delegator]
			if rest != nil && rest.Sign() > 0 {
				setActual(d.Token, rest, fromDeposit)
				if fromDeposit.Sign() > 0 {
					updateCounter(fromDeposit, newVal, d.Token, d.Stake)
					updatedDFrom = append(updatedDFrom, d) //cache
					pRecords = append(pRecords, &PenaltyRecord{
						Address: d.Delegator,
						Amount:  new(big.Int).Set(fromDeposit),
					})
				}
			}
		}
		for _, d := range updatedDFrom {
			newVal.UpdateDelegationFrom(d)
		}
	}
	return
}

func exportDoubleSigner(doubleSign EvidenceDoubleSign, hashPairs []hashSignPair) common.Address {
	_, consAddr, err := verifySign(doubleSign.Round, doubleSign.RoundIndex, hashPairs[0])
	if err != nil {
		log.Error("illegal evidence for double sign", "round", doubleSign.Round, "roundIndex", doubleSign.RoundIndex)
	}
	_, consAddrDup, err := verifySign(doubleSign.Round, doubleSign.RoundIndex, hashPairs[1])
	if err != nil {
		log.Error("illegal evidence for double sign", "round", doubleSign.Round, "roundIndex", doubleSign.RoundIndex)
	}
	if consAddr != (common.Address{}) && (consAddr == consAddrDup) {
		return consAddr
	}
	return common.Address{}
}

func getSignaturePublicKey(data []byte, sig []byte) (*ecdsa.PublicKey, error) {
	hashData := crypto.Keccak256(data)
	pubkey, err := crypto.SigToPub(hashData, sig)
	if err != nil {
		return nil, err
	}
	return pubkey, nil
}

func verifySign(round *big.Int, roundIndex uint32, pair hashSignPair) (*ecdsa.PublicKey, common.Address, error) {
	var buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, roundIndex)
	payload := append(pair.Hash.Bytes(), append(round.Bytes(), buf...)...)
	vrfPk, err := getSignaturePublicKey(payload, pair.Sign)
	if err != nil {
		return nil, common.Address{}, err
	}
	consAddr := crypto.PubkeyToAddress(*vrfPk)
	return vrfPk, consAddr, nil
}
