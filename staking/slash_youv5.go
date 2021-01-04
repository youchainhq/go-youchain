/*
 * Copyright 2020 YOUCHAIN FOUNDATION LTD.
 * This file is part of the go-youchain library.
 *
 * The go-youchain library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The go-youchain library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the go-youchain library. If not, see <http://www.gnu.org/licenses/>.
 */

package staking

import (
	"encoding/binary"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"math/big"
)

// ucon vote type
const (
	VoteNone uint8 = iota
	Propose
	Prevote
	Precommit
	NextIndex
	Certificate
)

// slashingAndRecoveringYouV5 includes inactivity slashing and recover validators from expired expelling.
func slashingAndRecoveringYouV5(ctx *context) {
	if ctx.config.Version < params.YouV5 {
		return
	}

	num := ctx.header.Number.Uint64()
	all := ctx.db.GetValidatorsForUpdate()
	for _, val := range all {
		if val.Expelled && val.ExpelExpired < num {
			// recover
			recoverFromExpiredExpelling(ctx, val, num)
			continue
		}

		// inactivity check and slashing
		inactivitySlashing(ctx, val, num)
	}
}

func recoverFromExpiredExpelling(ctx *context, val *state.Validator, height uint64) {
	old := val.PartialCopy()
	val.Expelled = false
	val.ExpelExpired = 0
	updated := ctx.db.UpdateValidator(val, old)
	ctx.receipt.Logs = append(ctx.receipt.Logs, &types.Log{
		Address:     params.StakingModuleAddress,
		Topics:      []common.Hash{common.StringToHash(LogTopicRecoverFromExpiredExpelling), val.MainAddress().Hash()},
		Data:        common.BytesToHash(hexutil.Uint64ToBytes(old.ExpelExpired)).Bytes(),
		BlockNumber: height,
	})
	log.Info("recover from expired expelling", "val", old.MainAddress().String(), "expelExpired", old.ExpelExpired, "height", height, "updated", updated)
}

func inactivitySlashing(ctx *context, val *state.Validator, num uint64) {
	if val.Role == params.RoleHouse || val.IsOffline() {
		return
	}
	waitRounds := ctx.config.InactivityPenaltyWaitRounds
	if num-val.LastActive() <= waitRounds {
		return
	}
	logging.Warn("inactivitySlashingYouV5", "val", val.MainAddress().String(), "lastActive", val.LastActive(), "height", num, "waitRounds", waitRounds)
	logData := SlashDataV5{
		Type:        EventTypeInactive,
		MainAddress: val.MainAddress(),
	}
	// inactive
	penaltyAmount := new(big.Int)
	if ctx.config.PenaltyFractionForInactive > 0 {
		penaltyAmount = penaltyAmount.Div(new(big.Int).Mul(val.Token, big.NewInt(int64(ctx.config.PenaltyFractionForInactive))), big.NewInt(100))
	}

	logData.Total, logData.FromWithdraw, logData.FromDeposit = doPenalize(ctx.config, EvidenceTypeInactive, ctx.db, ctx.header, val, penaltyAmount, num)

	// receipt
	rlpData, err := rlp.EncodeToBytes(logData)
	if err != nil {
		log.Error("rlp encode SlashDataV5 failed", "err", err)
		return
	}
	ctx.receipt.Logs = append(ctx.receipt.Logs, &types.Log{
		Address:     params.StakingModuleAddress,
		Topics:      []common.Hash{common.StringToHash(LogTopicSlashing)},
		Data:        rlpData,
		BlockNumber: num,
	})
}

func (s *Staking) processDoubleSignV5(config *params.YouParams, currentDB *state.StateDB, header *types.Header, parentHeight uint64, evidence Evidence, receipt *types.Receipt, result *processedEvidencesResult, doubleSignedValidators map[common.Address]struct{}) {
	var doubleSign EvidenceDoubleSignV5
	if err := rlp.DecodeBytes(evidence.Data, &doubleSign); err != nil {
		logging.Error("rlp decode EvidenceDoubleSignV5 failed", "data", hexutil.Encode(evidence.Data), "err", err)
		return
	}

	if len(doubleSign.Signs) < 2 {
		return
	}

	log.Info("slashing", "type", EvidenceTypeDoubleSignV5, "parent", parentHeight, "eRound", doubleSign.Round, "eRoundIndex", doubleSign.RoundIndex, "sinerIdx", doubleSign.SignerIdx, "signs", len(doubleSign.Signs))
	switch {
	case doubleSign.Round == parentHeight:
		var signerAddr common.Address
		if addr := evidence.addr.Load(); addr != nil {
			signerAddr = addr.(common.Address)
			log.Debug("signer addr from cache", "addr", signerAddr.String())
		} else {
			vldReader, err := s.blockChain.LookBackVldReaderForRound(doubleSign.Round, doubleSign.VoteType == Certificate)
			if err != nil {
				logging.Warn("processDoubleSignV5 LookBackVldReaderForRound", "err", err)
				return
			}
			vs := vldReader.GetValidators()
			signer, exist := vs.GetByIndex(int(doubleSign.SignerIdx))
			if !exist {
				logging.Warn("invalid voter index", "idx", doubleSign.SignerIdx, "validatorsLen", vs.Len())
				return
			}
			pk, err := s.blsMgr.DecPublicKey(signer.BlsPubKey)
			if err != nil {
				return
			}

			var buf = make([]byte, 4)
			binary.BigEndian.PutUint32(buf, doubleSign.RoundIndex)
			roundbuf := append(new(big.Int).SetUint64(doubleSign.Round).Bytes(), buf...)
			for _, info := range doubleSign.Signs {
				payload := append(info.Hash.Bytes(), roundbuf...)
				sig, err := s.blsMgr.DecSignature(info.Sign)
				if err != nil {
					return
				}
				err = pk.Verify(payload, sig)
				if err != nil {
					return
				}
			}

			signerAddr = signer.MainAddress()
			evidence.addr.Store(signerAddr)
			log.Debug("signer addr after verify signatures ", "addr", signerAddr.String())
		}

		if signerAddr == (common.Address{}) {
			return
		}

		if _, ok := doubleSignedValidators[signerAddr]; ok {
			log.Debug("double sign, already processed", "addr", signerAddr.String())
			return
		}

		val := currentDB.GetValidatorByMainAddr(signerAddr)
		if val == nil {
			log.Info("processDoubleSignV5, validator not exist in current state", "addr", signerAddr.String())
			return
		}

		doubleSignedValidators[signerAddr] = struct{}{}

		penaltyAmount := new(big.Int).Div(new(big.Int).Mul(val.Token, new(big.Int).SetUint64(config.PenaltyFractionForDoubleSign)), big.NewInt(100))
		totalPenalty, affectedRecords, pRecords := doPenalize(config, EvidenceTypeDoubleSign, currentDB, header, val, penaltyAmount, doubleSign.Round)

		var affected int
		// penalty
		if totalPenalty.Cmp(bigZero) > 0 {
			affected++
			result.affectedValidators = append(result.affectedValidators, &signerAddr)
			logData := SlashDataV5{
				Type:         EventTypeDoubleSign,
				MainAddress:  val.MainAddress(),
				Total:        totalPenalty,
				FromWithdraw: affectedRecords,
				FromDeposit:  pRecords,
			}
			rlpData, err := rlp.EncodeToBytes(logData)
			if err == nil {
				receipt.Logs = append(receipt.Logs, &types.Log{
					Address:     params.StakingModuleAddress,
					Topics:      []common.Hash{common.StringToHash(LogTopicSlashing)},
					Data:        rlpData,
					BlockNumber: header.Number.Uint64(),
				})
			} else {
				log.Error("rlp encode SlashDataV5 failed", "err", err)
			}
		}

		if affected > 0 {
			result.confirmedEvidences = append(result.confirmedEvidences, evidence)
		} else {
			result.deletedEvidences = append(result.deletedEvidences, evidence)
		}

	case doubleSign.Round > parentHeight:
		result.pendingEvidences = append(result.pendingEvidences, evidence) // future evidences

	case doubleSign.Round < parentHeight:
		if parentHeight-doubleSign.Round <= config.MaxEvidenceExpiredIn {
			result.pendingEvidences = append(result.pendingEvidences, evidence)
		} else {
			log.Warn("evidence expired", "round", doubleSign.Round, "roundIndex", doubleSign.RoundIndex) // discard expired evidences
		}
	}
}
