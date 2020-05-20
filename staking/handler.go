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
	"fmt"
	"math/big"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/math"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
)

// 初始化，创建抵押
func handleCreate(ctx *core.MessageContext, payload []byte) error {
	tx := &TxCreateValidator{}
	if err := rlp.DecodeBytes(payload, tx); err != nil {
		return err
	}
	if err := tx.PreCheck(); err != nil {
		return err
	}

	//check operator
	if ctx.Msg.From() != tx.OperatorAddress {
		return errAuthorizationFailed
	}

	role := tx.Role
	cfg := &ctx.Cfg.CurrYouParams.StakingParams
	if cfg.SignatureRequired[role] && !tx.Verify(tx.Nonce, cfg.MasterAddress) {
		return errInvalidateMasterSign
	}

	threshold := cfg.MinSelfStakes[role]
	stake := params.YOUToStake(tx.Value)
	if stake.Uint64() < threshold {
		log.Error("errInsufficientSelfStaking", "value", tx.Value, "stake", stake.Uint64(), "threshold", threshold)
		return errInsufficientSelfStaking
	}
	// max total stakes
	if threshold = cfg.MaxStakes[role]; threshold > 0 && stake.Uint64() > threshold {
		log.Error("errStakesOverflow", "value", tx.Value, "stake", stake.Uint64(), "threshold", threshold)
		return errStakesOverflow
	}

	db := ctx.State
	callerAddress := ctx.Msg.From()
	number := ctx.Header.Number.Uint64() // for convenience

	mainAddress := state.PubToAddress(tx.MainPubKey)
	if mainAddress == (common.Address{}) {
		return errInvalidateMainPubKey
	}
	if val := db.GetValidatorByMainAddr(mainAddress); val != nil {
		log.Error("validator exists", "mainAddr", mainAddress.String())
		return errValidatorAlreadyExist
	}
	// does pending exist?
	pendingExist := db.PendingValidatorExist(mainAddress)
	if pendingExist {
		log.Error("pending validator exists", "mainAddr", mainAddress.String())
		return errValidatorAlreadyExist
	}

	if !core.CanTransfer(db, callerAddress, tx.Value) {
		log.Error("insufficient balance to deposit", "number", number, "mainAddr", mainAddress.String(), "caller", callerAddress.String(), "balance", db.GetBalance(callerAddress), "deposit", tx.Value.String())
		return errInsufficientBalanceForDeposit
	}

	log.Debug("handleCreate", "number", number, "mainAddr", mainAddress.String(), "caller", callerAddress.String(), "balance", db.GetBalance(callerAddress), "deposit", tx.Value.String(), "stake", stake, "blsPubKey", tx.BlsPubKey.String())

	// subtract balance and record this pending staking.
	db.SubBalance(callerAddress, tx.Value)
	db.AddStakingRecord(common.Address{}, mainAddress, ctx.Msg.TxHash(), tx.Value)
	db.AddLog(&types.Log{
		Address:     params.StakingModuleAddress,
		Topics:      []common.Hash{common.StringToHash(LogTopicCreate), mainAddress.Hash()},
		Data:        combinePendingStakingLogData(cfg.StakingTrieFrequency, number, tx.Value),
		BlockNumber: number,
	})

	log.Info("pengding create validator", "number", number, "mainAddr", mainAddress.String(), "stake", stake, "token", tx.Value)
	return nil
}

func handleUpdate(ctx *core.MessageContext, payload []byte) error {
	tx := TxUpdateValidator{}
	if err := rlp.DecodeBytes(payload, &tx); err != nil {
		return err
	}

	val, err := validatorTxBasicCheck(ctx, tx.MainAddress, &tx)
	if err != nil {
		return err
	}

	db := ctx.State
	var updated bool

	log.Debug("update validator", "mainAddr", val.MainAddress().String(), "name", tx.Name, "op", tx.OperatorAddress.String(), "coinbase", tx.Coinbase.String())
	// change operator
	if tx.OperatorAddress != (common.Address{}) && tx.OperatorAddress != val.OperatorAddress {
		updated = true
	}
	if tx.Coinbase != (common.Address{}) && val.Coinbase != tx.Coinbase {
		updated = true
	}
	if tx.Name != "" && tx.Name != val.Name {
		updated = true
	}
	//改为指针，以便支持默认值（不改此字段）
	if tx.AcceptDelegation != math.MaxUint8 && tx.AcceptDelegation != val.AcceptDelegation {
		updated = true
	}
	if tx.CommissionRate != math.MaxUint16 && tx.CommissionRate != val.CommissionRate {
		updated = true
	}
	if tx.RiskObligation != math.MaxUint16 && tx.RiskObligation != val.RiskObligation {
		updated = true
	}

	if !updated {
		return errNothingHappened
	}

	//records this pending staking
	db.AddStakingRecord(common.Address{}, tx.MainAddress, ctx.Msg.TxHash(), nil)
	number := ctx.Header.Number.Uint64() // for convenience
	db.AddLog(&types.Log{
		Address:     params.StakingModuleAddress,
		Topics:      []common.Hash{common.StringToHash(LogTopicUpdate), tx.MainAddress.Hash()},
		Data:        combinePendingStakingLogData(ctx.Cfg.CurrYouParams.StakingTrieFrequency, number, bigZero),
		BlockNumber: number,
	})

	log.Info("pending update validator", "number", number, "mainAddr", val.MainAddress().String(), "name", val.Name, "coinbase", val.Coinbase.String(), "AcceptDelegation", val.AcceptDelegation, "CommissionRate", val.CommissionRate)

	return nil
}

// handleDeposit deposit more token
func handleDeposit(ctx *core.MessageContext, payload []byte) error {
	tx := TxValidatorDeposit{}
	if err := rlp.DecodeBytes(payload, &tx); err != nil {
		return err
	}

	val, err := validatorTxBasicCheck(ctx, tx.MainAddress, &tx)
	if err != nil {
		return err
	}

	db := ctx.State
	if !core.CanTransfer(db, ctx.Msg.From(), tx.Value) {
		return errInsufficientBalanceForDeposit
	}

	currStaking := db.GetStakingRecordValue(common.Address{}, tx.MainAddress)
	if currStaking.Sign() == 0 {
		currStaking = val.Token
	}
	finalStaking := new(big.Int).Add(currStaking, tx.Value)
	// check max stakes
	stake := params.YOUToStake(finalStaking).Uint64()
	// max total stakes
	if threshold := ctx.Cfg.CurrYouParams.MaxStakes[val.Role]; threshold > 0 && stake > threshold {
		log.Error("errStakesOverflow", "value", finalStaking, "stake", stake, "threshold", threshold)
		return errStakesOverflow
	}

	number := ctx.Header.Number.Uint64() // for convenience

	db.SubBalance(ctx.Msg.From(), tx.Value)
	db.AddStakingRecord(common.Address{}, tx.MainAddress, ctx.Msg.TxHash(), finalStaking)
	db.AddLog(&types.Log{
		Address:     params.StakingModuleAddress,
		Topics:      []common.Hash{common.StringToHash(LogTopicDeposit), tx.MainAddress.Hash()},
		Data:        combinePendingStakingLogData(ctx.Cfg.CurrYouParams.StakingTrieFrequency, number, finalStaking),
		BlockNumber: number,
	})
	log.Info("pending validator deposit", "number", number, "val", val.MainAddress().String(), "oldToken", currStaking, "newToken", finalStaking)

	return nil
}

//handleWithdraw withdraw tokens to coinbase
func handleWithdraw(ctx *core.MessageContext, payload []byte) error {
	tx := TxValidatorWithdraw{}
	if err := rlp.DecodeBytes(payload, &tx); err != nil {
		return err
	}

	val, err := validatorTxBasicCheck(ctx, tx.MainAddress, &tx)
	if err != nil {
		return err
	}

	number := ctx.Header.Number.Uint64() // for convenience
	db := ctx.State
	currStaking := db.GetStakingRecordValue(common.Address{}, tx.MainAddress)
	if currStaking.Sign() == 0 {
		currStaking = val.SelfToken
	}

	log.Debug("withdraw", "number", number, "mainAddr", tx.MainAddress.String(), "recipient", tx.Recipient.String(), "value", tx.Value, "time", time.Now().Unix(), "headerTime", ctx.Header.Time)

	if currStaking.Cmp(tx.Value) < 0 {
		log.Error("withdraw", "number", number, "mainAddr", tx.MainAddress.String(), "check", "token", "old", currStaking, "want", tx.Value)
		return errInsufficientWithdraw
	}
	finalStaking := new(big.Int).Sub(currStaking, tx.Value)

	db.AddStakingRecord(common.Address{}, tx.MainAddress, ctx.Msg.TxHash(), finalStaking)
	db.AddLog(&types.Log{
		Address:     params.StakingModuleAddress,
		Topics:      []common.Hash{common.StringToHash(LogTopicWithdraw), tx.MainAddress.Hash()},
		Data:        combinePendingStakingLogData(ctx.Cfg.CurrYouParams.StakingTrieFrequency, number, finalStaking),
		BlockNumber: number,
	})
	log.Info("pending validator withdraw", "number", number, "val", val.MainAddress().String(), "oldToken", currStaking, "newToken", finalStaking)

	return nil
}

func handleSettle(ctx *core.MessageContext, payload []byte) error {
	tx := TxValidatorSettle{}
	if err := rlp.DecodeBytes(payload, &tx); err != nil {
		return err
	}
	val, err := validatorTxBasicCheck(ctx, tx.MainAddress, &tx)
	if err != nil {
		return err
	}

	if val.Status != params.ValidatorOnline {
		return errValidatorIsOffline
	}

	number := ctx.Header.Number.Uint64() // for convenience
	db := ctx.State
	db.AddStakingRecord(common.Address{}, tx.MainAddress, ctx.Msg.TxHash(), nil)
	db.AddLog(&types.Log{
		Address:     params.StakingModuleAddress,
		Topics:      []common.Hash{common.StringToHash(LogTopicSettle), tx.MainAddress.Hash()},
		Data:        combinePendingStakingLogData(ctx.Cfg.CurrYouParams.StakingTrieFrequency, number, bigZero),
		BlockNumber: number,
	})
	return nil
}

// change validator's status
func handleChangeStatus(ctx *core.MessageContext, payload []byte) error {
	tx := TxValidatorChangeStatus{}
	if err := rlp.DecodeBytes(payload, &tx); err != nil {
		return err
	}
	val, err := validatorTxBasicCheck(ctx, tx.MainAddress, &tx)
	if err != nil {
		return err
	}

	number := ctx.Header.Number.Uint64() // for convenience
	db := ctx.State
	pendingExist := db.PendingValidatorExist(tx.MainAddress)
	if pendingExist {
		return errPendingExistForChangeStatus
	}

	cfg := &ctx.Cfg.CurrYouParams.StakingParams
	effectsOn := ((number/cfg.StakingTrieFrequency)+1)*cfg.StakingTrieFrequency - 1
	// denied for changing status of an expelled validator
	if val.Expelled && (effectsOn < val.ExpelExpired) {
		return errValidatorIsExpelled
	}

	if val.Status == tx.Status {
		return fmt.Errorf("validator is already in status: %d", val.Status)
	}

	if tx.Status == params.ValidatorOnline && val.Stake.Uint64() < cfg.MinStakes[val.Role] {
		return errInsufficientStakeToOnline
	}

	db.AddStakingRecord(common.Address{}, tx.MainAddress, ctx.Msg.TxHash(), nil)
	db.AddLog(&types.Log{
		Address:     params.StakingModuleAddress,
		Topics:      []common.Hash{common.StringToHash(LogTopicWithdraw), tx.MainAddress.Hash()},
		Data:        combinePendingStakingLogData(ctx.Cfg.CurrYouParams.StakingTrieFrequency, number, bigZero),
		BlockNumber: number,
	})

	log.Info("pending validator status change", "number", number, "mainAddr", tx.MainAddress.String(), "tx.Status", tx.Status)
	return nil
}

func validatorTxBasicCheck(ctx *core.MessageContext, vAddr common.Address, msg Msg) (*state.Validator, error) {
	if err := msg.PreCheck(); err != nil {
		return nil, err
	}

	db := ctx.State
	var val *state.Validator
	if val = db.GetValidatorByMainAddr(vAddr); val == nil {
		log.Error("validator not found", "mainAddr", vAddr.String())
		return nil, errValidatorNotFound
	}

	if !val.IsOperator(ctx.Msg.From()) {
		return nil, errAuthorizationFailed
	}

	cfg := &ctx.Cfg.CurrYouParams.StakingParams
	if cfg.SignatureRequired[val.Role] && !msg.Verify(ctx.Msg.Nonce(), cfg.MasterAddress) {
		return nil, errInvalidateMasterSign
	}
	return val, nil
}
