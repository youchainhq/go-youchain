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
	"math/big"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
)

func handleDelegationAdd(ctx *core.MessageContext, payload []byte) error {
	d, err := decodeTxDelegation(payload)
	if err != nil {
		return err
	}
	db, delegator, validator, exist, err := commonVarForDelegation(ctx, d.Validator)
	if err != nil {
		return err
	}
	if validator.AcceptDelegation != params.AcceptDelegation {
		return errNotAcceptDelegation
	}
	if validator.Expelled {
		return errValidatorIsExpelled
	}
	if delegator == d.Validator {
		return errSeftDelegating
	}
	yp := ctx.Cfg.CurrYouParams
	if d.Value.Cmp(yp.MinDelegationTokens) < 0 {
		return errDelegationValueTooLow
	}
	//check balance
	if !core.CanTransfer(db, delegator, d.Value) {
		return errInsufficientBalanceForDelegate
	}

	// check the limitation
	// whether exist delegation from delegator to validator
	pendingExist := db.PendingRelationshipExist(delegator, d.Validator)
	// if already exist, then delegating more tokens is ok;
	// otherwise it should follow the limitation rule.
	if !(exist || pendingExist) {
		dcnt := db.GetCountOfDelegateTo(delegator) + db.DelegatorPendingCount(delegator)
		if dcnt >= yp.MaxDelegationForDelegator {
			return errNoMoreDelegationsForDelegator
		}
		vcnt := validator.Delegations.Len() + db.ValidatorPendingCount(d.Validator)
		if vcnt >= yp.MaxDelegationForValidator {
			return errNoMoreDelegationsForValidator
		}
	}

	// check the max threshold of stakes of the validator, if no error, then update it.
	// this MUST BE the last check.
	err = checkAndUpdateTotalPendingStakesOfValidator(ctx.Cfg.CurrYouParams, db, validator, d.Value)
	if err != nil {
		return err
	}

	// calc the total delegating tokens after this tx for pending record
	currValue := new(big.Int)
	if exist || pendingExist {
		//Note: (pendingExist is false) ≠ (there's no pending record on the staking trie)
		// BECAUSE the pendingExist ONLY indicates the unique relationship between delegator and validator
		value := db.GetStakingRecordValue(delegator, d.Validator)
		if value.Sign() == 0 {
			if dfrom := validator.GetDelegationFrom(delegator); dfrom != nil {
				value = dfrom.Token
			}
		}
		currValue = currValue.Set(value)
	}
	finalValue := new(big.Int).Add(currValue, d.Value)
	// finally, apply the state change
	db.SubBalance(delegator, d.Value)
	if !(exist || pendingExist) {
		db.AddPendingRelationship(delegator, d.Validator)
	}
	addPendingDelegationRecordAndLog(ctx, db, delegator, d.Validator, finalValue)

	return nil
}

func handleDelegationSub(ctx *core.MessageContext, payload []byte) error {
	d, err := decodeTxDelegation(payload)
	if err != nil {
		return err
	}
	db, delegator, validator, exist, err := commonVarForDelegation(ctx, d.Validator)
	if err != nil {
		return err
	}
	if delegator == d.Validator {
		return errSeftDelegating
	}

	// check value
	// first get from pending, if not exist pending value, then try get from validator.
	currValue := db.GetStakingRecordValue(delegator, d.Validator)
	if currValue.Sign() == 0 { // means no pending
		if !exist {
			return errDelegationNotExist
		}
		// current delegation exist, get current value
		dfrom := validator.GetDelegationFrom(delegator)
		currValue = dfrom.Token
	}
	if d.Value.Cmp(currValue) > 0 {
		return errInsufficientValueForUnbind
	}

	// update pending total tokens of validator,
	// no error for sub.
	deltaTokens := new(big.Int).Neg(d.Value)
	_ = checkAndUpdateTotalPendingStakesOfValidator(ctx.Cfg.CurrYouParams, db, validator, deltaTokens)

	//Note: will not deletes any relationship currently, just for simplicity.
	finalValue := new(big.Int).Sub(currValue, d.Value)
	addPendingDelegationRecordAndLog(ctx, db, delegator, d.Validator, finalValue)
	return nil
}

func handleDelegationSettle(ctx *core.MessageContext, payload []byte) error {
	var d TxDelegationSettle
	err := rlp.DecodeBytes(payload, &d)
	if err != nil {
		return err
	}
	if err = d.PreCheck(); err != nil {
		return err
	}
	db, delegator, _, exist, err := commonVarForDelegation(ctx, d.Validator)
	if err != nil {
		return err
	}
	if !exist {
		return errDelegationNotExist
	}

	addPendingDelegationRecordAndLog(ctx, db, delegator, d.Validator, nil)
	return nil
}

func checkAndUpdateTotalPendingStakesOfValidator(cfg *params.YouParams, db *state.StateDB, val *state.Validator, deltaTokens *big.Int) error {
	totalTokens := db.GetStakingRecordValue(common.Address{}, val.MainAddress())
	if totalTokens.Sign() == 0 {
		totalTokens.Set(val.Token)
	}
	totalTokens.Add(totalTokens, deltaTokens)
	if deltaTokens.Sign() > 0 {
		stake := params.YOUToStake(totalTokens).Uint64()
		if threshold := cfg.MaxStakes[val.Role]; threshold > 0 && stake > threshold {
			log.Error("errStakesOverflow", "newAdded", deltaTokens, "totalTokens", totalTokens, "stake", stake, "threshold", threshold)
			return errStakesOverflow
		}
	}

	//
	db.AddStakingRecord(common.Address{}, val.MainAddress(), common.Hash{}, totalTokens)
	return nil
}

func commonVarForDelegation(ctx *core.MessageContext, valAddr common.Address) (*state.StateDB, common.Address, *state.Validator, bool, error) {
	db := ctx.State
	validator := db.GetValidatorByMainAddr(valAddr)
	if validator == nil {
		return db, common.Address{}, nil, false, errValidatorNotFound
	}
	delegator := ctx.Msg.From()
	exist := validator.Delegations.Exist(delegator)
	return db, delegator, validator, exist, nil
}

func addPendingDelegationRecordAndLog(ctx *core.MessageContext, db *state.StateDB, delegator, validator common.Address, newFinalValue *big.Int) {
	db.AddStakingRecord(delegator, validator, ctx.Msg.TxHash(), newFinalValue)
	//log
	yp := ctx.Cfg.CurrYouParams
	number := ctx.Header.Number.Uint64()
	logData := combinePendingStakingLogData(yp.StakingTrieFrequency, number, newFinalValue)
	db.AddLog(&types.Log{
		Address:     *ctx.Msg.To(),
		Topics:      []common.Hash{common.StringToHash(LogTopicDelegationPending)},
		Data:        logData,
		BlockNumber: number,
	})
}

func decodeTxDelegation(payload []byte) (*TxDelegation, error) {
	var d TxDelegation
	err := rlp.DecodeBytes(payload, &d)
	if err != nil {
		return nil, err
	}
	if err = d.PreCheck(); err != nil {
		return nil, err
	}
	return &d, nil
}

func combinePendingStakingLogData(frequency, currentHeight uint64, finalValue *big.Int) []byte {
	if finalValue == nil {
		finalValue = bigZero
	}
	r := currentHeight / frequency
	effectsOn := (r+1)*frequency - 1
	left := make([]byte, 8)
	binary.BigEndian.PutUint64(left, effectsOn)
	h := common.BigToHash(finalValue)
	data := h[:]
	copy(data[:8], left)
	return data
}
