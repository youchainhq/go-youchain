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
	"github.com/youchainhq/go-youchain/common/math"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
)

type teHandlerFn func(ctx *messageContext, payload []byte) error

// static take effect handlers mapping
var teHandlers map[ActionType]teHandlerFn

func init() {
	teHandlers = make(map[ActionType]teHandlerFn)
	teHandlers[ValidatorCreate] = teCreate
	teHandlers[ValidatorUpdate] = teUpdate
	teHandlers[ValidatorDeposit] = teDeposit
	teHandlers[ValidatorWithDraw] = teWithdraw
	teHandlers[ValidatorChangeStatus] = teChangeStatus
	teHandlers[ValidatorSettle] = teNoop

	teHandlers[DelegationAdd] = teDelegationAdd
	teHandlers[DelegationSub] = teDelegationSub
	teHandlers[DelegationSettle] = teNoop
}

type messageContext struct {
	Msg     core.Message
	State   *state.StateDB
	Cfg     *params.YouParams
	Header  *types.Header
	Receipt *types.Receipt
}

func getTeHandler(action ActionType) teHandlerFn {
	h, exist := teHandlers[action]
	if exist {
		return h
	}
	return func(ctx *messageContext, payload []byte) error {
		return errUnsupportedActionType
	}
}

// Note: there's no need to do some basic check.
func takeEffectEntry(ctx *messageContext) {
	var msg Message
	_ = rlp.DecodeBytes(ctx.Msg.Data(), &msg)
	err := getTeHandler(msg.Action)(ctx, msg.Payload)
	if err != nil {
		logging.Error("take effect tx failed", "txhash", ctx.Msg.TxHash().String(), "action", msg.Action, "err", err)
	}
}

func teCreate(ctx *messageContext, payload []byte) error {
	tx := &TxCreateValidator{}
	_ = rlp.DecodeBytes(payload, tx)
	stake := params.YOUToStake(tx.Value)
	ctx.State.CreateValidator(tx.Name, tx.OperatorAddress, tx.Coinbase, tx.Role, tx.MainPubKey, tx.BlsPubKey, tx.Value, stake, tx.AcceptDelegation, tx.CommissionRate, tx.RiskObligation, params.ValidatorOffline)
	return nil
}

func teUpdate(ctx *messageContext, payload []byte) error {
	tx := &TxUpdateValidator{}
	_ = rlp.DecodeBytes(payload, tx)
	old := ctx.State.GetValidatorByMainAddr(tx.MainAddress)
	newVal := old.PartialCopy()
	if tx.Name != "" {
		newVal.Name = tx.Name
	}
	if tx.OperatorAddress != (common.Address{}) {
		newVal.OperatorAddress = tx.OperatorAddress
	}
	if tx.Coinbase != (common.Address{}) {
		newVal.Coinbase = tx.Coinbase
	}
	if tx.AcceptDelegation != math.MaxUint8 {
		newVal.AcceptDelegation = tx.AcceptDelegation
	}
	if tx.CommissionRate != math.MaxUint16 {
		newVal.CommissionRate = tx.CommissionRate
	}
	if tx.RiskObligation != math.MaxUint16 {
		newVal.RiskObligation = tx.RiskObligation
	}
	ctx.State.UpdateValidator(newVal, old)
	return nil
}

func teDeposit(ctx *messageContext, payload []byte) error {
	tx := &TxValidatorDeposit{}
	_ = rlp.DecodeBytes(payload, &tx)
	old := ctx.State.GetValidatorByMainAddr(tx.MainAddress)
	newVal := old.PartialCopy()
	newVal.SelfToken.Add(newVal.SelfToken, tx.Value)
	newStake := params.YOUToStake(newVal.SelfToken)
	delta := new(big.Int).Sub(newStake, newVal.SelfStake)
	newVal.SelfStake.Set(newStake)
	//update total
	newVal.Token.Add(newVal.Token, tx.Value)
	newVal.Stake.Add(newVal.Stake, delta)

	// before update validator, check the max stakes threshold
	stake := newVal.Stake.Uint64()
	if threshold := ctx.Cfg.MaxStakes[newVal.Role]; threshold > 0 && stake > threshold {
		log.Error("errStakesOverflow", "value", newVal.Token, "stake", stake, "threshold", threshold)
		if ctx.Cfg.Version >= params.YouV5 {
			// when deposit failed, return the detained tokens.
			ctx.State.AddBalance(ctx.Msg.From(), tx.Value)
		}
		// log on failed
		//add a flag for this log
		t1 := old.MainAddress().Hash().Bytes()
		t1[0] = 0x1
		ctx.Receipt.Logs = append(ctx.Receipt.Logs, &types.Log{
			Address: params.StakingModuleAddress,
			Topics:  []common.Hash{common.StringToHash(LogTopicDepositFailed), common.BytesToHash(t1)},
			TxHash:  ctx.Msg.TxHash(),
		})
		return nil
	}

	ctx.State.UpdateValidator(newVal, old)
	return nil
}

func teWithdraw(ctx *messageContext, payload []byte) error {
	tx := &TxValidatorWithdraw{}
	_ = rlp.DecodeBytes(payload, &tx)
	old := ctx.State.GetValidatorByMainAddr(tx.MainAddress)
	newVal := old.PartialCopy()

	var changed bool
	withdrawToken := tx.Value
	if withdrawToken.Cmp(newVal.SelfToken) > 0 {
		changed = true
		withdrawToken = new(big.Int).Set(newVal.SelfToken)
	}
	newVal.SelfToken.Sub(newVal.SelfToken, withdrawToken)
	newStake := params.YOUToStake(newVal.SelfToken)
	delta := new(big.Int).Sub(newVal.SelfStake, newStake)
	newVal.SelfStake.Set(newStake)
	if newVal.IsOnline() &&
		(newStake.Uint64() < ctx.Cfg.MinSelfStakes[newVal.Role] || newVal.Stake.Uint64() < ctx.Cfg.MinStakes[newVal.Role]+delta.Uint64()) {
		changed = true
		// force to offline
		newVal.Status = params.ValidatorOffline
	}
	//update total
	newVal.Token.Sub(newVal.Token, withdrawToken)
	newVal.Stake.Sub(newVal.Stake, delta)

	ctx.State.UpdateValidator(newVal, old)

	addWithdrawLog(ctx, newVal, tx.Recipient, common.Address{}, newVal.SelfToken, newVal.SelfStake, withdrawToken, delta, changed, newVal.Status, 0)
	return nil
}

func teChangeStatus(ctx *messageContext, payload []byte) error {
	tx := &TxValidatorChangeStatus{}
	_ = rlp.DecodeBytes(payload, &tx)
	old := ctx.State.GetValidatorByMainAddr(tx.MainAddress)
	// check total stake again
	if tx.Status == params.ValidatorOnline && old.Stake.Uint64() < ctx.Cfg.MinStakes[old.Role] {
		// log on failed
		ctx.Receipt.Logs = append(ctx.Receipt.Logs, &types.Log{
			Address: params.StakingModuleAddress,
			Topics:  []common.Hash{common.StringToHash(LogTopicChangeStatusFailed), old.MainAddress().Hash()},
			TxHash:  ctx.Msg.TxHash(),
		})
		return nil
	}
	newVal := old.PartialCopy()
	newVal.Status = tx.Status
	if ctx.Header.CurrVersion >= params.YouV5 {
		newVal.UpdateLastActive(ctx.Header.Number.Uint64())
	}
	ctx.State.UpdateValidator(newVal, old)
	return nil
}

// teNoop is for settle transaction, do nothing here.
// the related transaction will trigger a settleValidatorRewards as all the other transactions do,
// so these settle transactions are NOT so called useless!
func teNoop(ctx *messageContext, payload []byte) error {
	return nil
}

func teDelegationAdd(ctx *messageContext, payload []byte) error {
	d, _ := decodeTxDelegation(payload)
	db := ctx.State
	val := db.GetValidatorByMainAddr(d.Validator)
	delegator := ctx.Msg.From()
	if val.Expelled || val.AcceptDelegation == params.NotAcceptDelegation {
		if ctx.Cfg.Version >= params.YouV5 {
			// when deposit failed, return the detained tokens.
			ctx.State.AddBalance(delegator, d.Value)
		}
		// log on failed
		ctx.Receipt.Logs = append(ctx.Receipt.Logs, &types.Log{
			Address: params.StakingModuleAddress,
			Topics:  []common.Hash{common.StringToHash(LogTopicDelegationAddFailed), delegator.Hash()},
			TxHash:  ctx.Msg.TxHash(),
		})
		return nil
	}

	// check max threshold again
	totalTokens := new(big.Int).Set(val.Token)
	totalTokens.Add(totalTokens, d.Value)
	stake := params.YOUToStake(totalTokens).Uint64()
	if threshold := ctx.Cfg.MaxStakes[val.Role]; threshold > 0 && stake > threshold {
		if ctx.Cfg.Version >= params.YouV5 {
			// when deposit failed, return the detained tokens.
			ctx.State.AddBalance(delegator, d.Value)
		}
		// over flow
		//add a flag for this log
		t1 := delegator.Hash().Bytes()
		t1[0] = 0x1
		ctx.Receipt.Logs = append(ctx.Receipt.Logs, &types.Log{
			Address: params.StakingModuleAddress,
			Topics:  []common.Hash{common.StringToHash(LogTopicDelegationAddFailed), common.BytesToHash(t1)},
			TxHash:  ctx.Msg.TxHash(),
		})
		return nil
	}

	// just update it
	db.UpdateDelegation(delegator, val, d.Value)
	return nil
}

func teDelegationSub(ctx *messageContext, payload []byte) error {
	d, _ := decodeTxDelegation(payload)
	db := ctx.State
	delegator := ctx.Msg.From()
	val := db.GetValidatorByMainAddr(d.Validator)
	dfrom := val.GetDelegationFrom(delegator)

	withdrawToken := d.Value
	var changed bool
	if dfrom == nil {
		changed = true
		withdrawToken.SetUint64(0)
	} else if withdrawToken.Cmp(dfrom.Token) > 0 {
		// not enough, may be due to penalty, etc..
		changed = true
		withdrawToken = new(big.Int).Set(dfrom.Token)
	}
	if withdrawToken.Sign() <= 0 {
		// log on failed
		ctx.Receipt.Logs = append(ctx.Receipt.Logs, &types.Log{
			Address: params.StakingModuleAddress,
			Topics:  []common.Hash{common.StringToHash(LogTopicDelegationSubFailed), delegator.Hash()},
			TxHash:  ctx.Msg.TxHash(),
		})
		return nil
	}

	// rehearse the withdraw for more business check
	remainToken := new(big.Int).Sub(dfrom.Token, withdrawToken)
	// If remain token not zero, AND (less than MinDelegationTokens OR the validator is offline)
	// then force to withdraw all.
	if remainToken.Sign() > 0 &&
		(remainToken.Cmp(ctx.Cfg.MinDelegationTokens) < 0 || val.IsOffline()) {
		changed = true
		withdrawToken.Add(withdrawToken, remainToken)
	}
	// a - b = a + (-b)
	negWithdraw := new(big.Int).Neg(withdrawToken)
	newVal, newDFrom, delta, status := db.UpdateDelegation(delegator, val, negWithdraw)
	stakeDelta := new(big.Int).Neg(delta)
	// check validator final total stake
	if newVal.IsOnline() && newVal.Stake.Uint64() < ctx.Cfg.MinStakes[newVal.Role] {
		val := newVal.PartialCopy()
		newVal.Status = params.ValidatorOffline // force to offline
		db.UpdateValidator(newVal, val)
	}

	addWithdrawLog(ctx, newVal, delegator, delegator, newDFrom.Token, newDFrom.Stake, withdrawToken, stakeDelta, changed, newVal.Status, uint8(status))
	return nil
}

func addWithdrawLog(ctx *messageContext, newVal *state.Validator, receipt, delegator common.Address, newToken, newStake, withdrawToken, stakeDelta *big.Int, changed bool, vStatus, dStatus uint8) {
	creationHeight := ctx.Header.Number.Uint64()
	completionDelay := ctx.Cfg.WithdrawDelay
	completionHeight := creationHeight + completionDelay

	if newVal.ExpelExpired > completionHeight { //被驱逐节点，提现延迟, 并到账不早于解锁时间
		completionDelay = newVal.ExpelExpired + 1
	}

	record := state.NewWithdrawRecord()
	record.Operator = ctx.Msg.From()
	record.Nonce = ctx.Msg.Nonce()
	record.Validator = newVal.MainAddress()
	record.Delegator = delegator
	record.Recipient = receipt
	record.InitialBalance = new(big.Int).Set(withdrawToken)
	record.FinalBalance = new(big.Int).Set(withdrawToken)
	record.Finished = 0
	record.CreationHeight = creationHeight
	record.CompletionHeight = completionHeight
	record.TxHash = ctx.Msg.TxHash()

	// update db
	ctx.State.AddWithdrawRecord(record)

	// handle different
	var topic, progLogMsg string
	isValidator := delegator == (common.Address{})
	if isValidator {
		topic = LogTopicWithdrawEffect
		progLogMsg = "validator withdraw record"
	} else {
		topic = LogTopicDelegationSubEffect
		progLogMsg = "delegator withdraw record"
	}

	// build withdraw log
	data := getWithdrawLogData(completionHeight, stakeDelta.Uint64(), withdrawToken, changed, vStatus, dStatus)
	rLog := &types.Log{
		Address:     params.StakingModuleAddress,
		Topics:      []common.Hash{common.StringToHash(topic), newVal.MainAddress().Hash()},
		Data:        data,
		BlockNumber: creationHeight,
	}
	if isValidator {
		rLog.Topics = append(rLog.Topics, delegator.Hash())
	}
	// append log to current end-block receipt.
	ctx.Receipt.Logs = append(ctx.Receipt.Logs)

	log.Info(progLogMsg, "operator", ctx.Msg.From(), "val", newVal.MainAddress().String(), "receipt", receipt, "withdrawToken", withdrawToken, "newToken", newToken, "stakeDelta", stakeDelta, "newStake", newStake, "creationHeight", creationHeight, "complete", completionHeight, "withdrawAmountChanged", changed)
}

// getWithdrawLogData builds a withdraw log:
// [0,8)			[8,16)			[16,28)    		[28]	[29]				[30]			[31]
// completionHeight stakeReduced	tokenWithdrawn	changed	validatorStatus		delegatorStatus	 --
func getWithdrawLogData(completionHeight, stakeReduced uint64, withdrawnToken *big.Int, changed bool, vStatus, dStatus uint8) []byte {
	data := make([]byte, common.HashLength)
	binary.BigEndian.PutUint64(data[:8], completionHeight)
	binary.BigEndian.PutUint64(data[8:16], stakeReduced)
	bs := withdrawnToken.Bytes()
	copy(data[28-len(bs):28], bs)
	if changed {
		data[28] = 0x1
	}
	data[29] = vStatus
	data[30] = dStatus
	return data
}
