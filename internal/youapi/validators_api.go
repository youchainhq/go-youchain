// Copyright 2020 YOUCHAIN FOUNDATION LTD.
// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package youapi

import (
	"context"
	"github.com/youchainhq/go-youchain/common/math"
	"sort"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rpc"
	"github.com/youchainhq/go-youchain/staking"
)

func (y *PublicMainApi) ValidatorByMainAddress(ctx context.Context, blockNr rpc.BlockNumber, mainAddress common.Address) (*state.DumpValidator, error) {
	db, _, err := y.c.StateAndHeaderByNumber(ctx, blockNr)
	if db == nil || err != nil {
		return nil, err
	}
	val := db.GetValidatorByMainAddr(mainAddress)
	if val == nil {
		return nil, err
	}

	dump := val.Dump()
	return &dump, nil
}

func (y *PublicMainApi) ValidatorsStat(ctx context.Context, blockNr rpc.BlockNumber) (map[params.ValidatorRole]state.DumpValidatorsStatItem, error) {
	db, _, err := y.c.StateAndHeaderByNumber(ctx, blockNr)
	if db == nil || err != nil {
		return nil, err
	}
	stat, err := db.GetValidatorsStat()
	if err != nil {
		return nil, err
	}
	return stat.Dump().Roles, nil
}

func (y *PublicMainApi) GetWithdrawRecords(ctx context.Context, blockNr rpc.BlockNumber) ([]*state.DumpWithdrawRecord, error) {
	db, _, err := y.c.StateAndHeaderByNumber(ctx, blockNr)
	if db == nil || err != nil {
		return nil, err
	}
	queue := db.GetWithdrawQueue()
	dumpRecords := make([]*state.DumpWithdrawRecord, queue.Len())
	for i, r := range queue.Records {
		dumpRecords[i] = r.Dump()
	}
	return dumpRecords, nil
}

func (y *PublicMainApi) Validators(ctx context.Context, role uint8, page, pageSize int, blockNr rpc.BlockNumber) ([]*state.DumpValidator, error) {
	db, _, err := y.c.StateAndHeaderByNumber(ctx, blockNr)
	if db == nil || err != nil {
		return nil, err
	}
	validators := db.GetValidators()
	sort.Sort(validators)

	if page < 0 {
		page = 0
	}

	if pageSize > 100 {
		pageSize = 100
	}

	if pageSize < 1 {
		pageSize = 1
	}

	offset := page * pageSize
	var dump []*state.DumpValidator
	counter := 0
	for _, val := range validators.List() {
		if val.Role == params.ValidatorRole(role) || role == 0 {
			if counter >= offset {
				if len(dump) < pageSize {
					item := val.Dump()
					dump = append(dump, &item)
				} else {
					break
				}
			}
			counter++
		}
	}
	return dump, nil
}

//build tx.data
func (y *PublicMainApi) CreateValidator(ctx context.Context, nonce uint64, name string, operator, coinbase common.Address, mainPubKey, blsPubKey hexutil.Bytes, value hexutil.Big, role uint8, acceptDelegation, commissionRate, riskObligation uint16) (hexutil.Bytes, error) {
	return y.createValidator(ctx, nonce, name, operator, coinbase, mainPubKey, blsPubKey, value, role, acceptDelegation, commissionRate, riskObligation)
}

func (y *PublicMainApi) createValidator(ctx context.Context, nonce uint64, name string, operatorAddress, coinbase common.Address, mainPubKey, blsPubKey hexutil.Bytes, value hexutil.Big, role uint8, acceptDelegation, commissionRate, riskObligation uint16) (hexutil.Bytes, error) {
	msg := &staking.TxCreateValidator{
		Name:             name,
		OperatorAddress:  operatorAddress,
		Coinbase:         coinbase,
		BlsPubKey:        blsPubKey,
		MainPubKey:       mainPubKey,
		Value:            value.ToInt(),
		Role:             params.ValidatorRole(role),
		Nonce:            nonce,
		AcceptDelegation: acceptDelegation,
		CommissionRate:   commissionRate,
		RiskObligation:   riskObligation,
	}

	return staking.EncodeMessage(staking.ValidatorCreate, msg)
}

//build tx.data
func (y *PublicMainApi) UpdateValidator(ctx context.Context, nonce uint64, name string, mainAddress, operator, coinbase common.Address, acceptDelegation, commissionRate, riskObligation *uint16) (hexutil.Bytes, error) {
	return y.updateValidator(ctx, nonce, name, mainAddress, operator, coinbase, acceptDelegation, commissionRate, riskObligation)
}

func (y *PublicMainApi) updateValidator(ctx context.Context, nonce uint64, name string, mainAddress, operatorAddress, coinbase common.Address, acceptDelegation, commissionRate, riskObligation *uint16) (hexutil.Bytes, error) {
	temp := make([]uint16, 3)
	for i, value := range []*uint16{acceptDelegation, commissionRate, riskObligation} {
		if value == nil {
			temp[i] = math.MaxUint16
		} else {
			temp[i] = *value
		}
	}
	msg := &staking.TxUpdateValidator{
		Name:             name,
		MainAddress:      mainAddress,
		OperatorAddress:  operatorAddress,
		Coinbase:         coinbase,
		Nonce:            nonce,
		AcceptDelegation: temp[0],
		CommissionRate:   temp[1],
		RiskObligation:   temp[2],
	}

	return staking.EncodeMessage(staking.ValidatorUpdate, msg)
}

//build tx.data
func (y *PublicMainApi) DepositValidator(ctx context.Context, nonce uint64, mainAddress common.Address, value hexutil.Big) (hexutil.Bytes, error) {
	msg := &staking.TxValidatorDeposit{
		MainAddress: mainAddress,
		Value:       value.ToInt(),
		Nonce:       nonce,
	}

	return staking.EncodeMessage(staking.ValidatorDeposit, msg)
}

//build tx.data
func (y *PublicMainApi) WithdrawValidator(ctx context.Context, nonce uint64, mainAddress, withdraw common.Address, value hexutil.Big) (hexutil.Bytes, error) {
	msg := &staking.TxValidatorWithdraw{
		MainAddress: mainAddress,
		Recipient:   withdraw,
		Value:       value.ToInt(),
		Nonce:       nonce,
	}

	return staking.EncodeMessage(staking.ValidatorWithDraw, msg)
}

//build tx.data
func (y *PublicMainApi) ChangeStatusValidator(ctx context.Context, nonce uint64, mainAddress common.Address, status uint8) (hexutil.Bytes, error) {
	msg := &staking.TxValidatorChangeStatus{
		MainAddress: mainAddress,
		Status:      status,
		Nonce:       nonce,
	}

	return staking.EncodeMessage(staking.ValidatorChangeStatus, msg)
}

//build tx.data
func (y *PublicMainApi) SettleValidator(ctx context.Context, mainAddress common.Address) (hexutil.Bytes, error) {
	msg := &staking.TxValidatorSettle{
		MainAddress: mainAddress,
	}

	return staking.EncodeMessage(staking.ValidatorSettle, msg)
}
