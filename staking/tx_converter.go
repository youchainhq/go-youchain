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
	"errors"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
)

var _ core.TxConverter = &TxConverter{}

var errUnsupportedActionType = errors.New("unsupported action type")

type handlerFn func(ctx *core.MessageContext, payload []byte) error

// static handlers mapping
var handlers map[ActionType]handlerFn

func init() {
	handlers = make(map[ActionType]handlerFn)
	handlers[ValidatorCreate] = handleCreate
	handlers[ValidatorUpdate] = handleUpdate
	handlers[ValidatorDeposit] = handleDeposit
	handlers[ValidatorWithDraw] = handleWithdraw
	handlers[ValidatorChangeStatus] = handleChangeStatus
	handlers[ValidatorSettle] = handleSettle //无需签名

	handlers[DelegationAdd] = handleDelegationAdd
	handlers[DelegationSub] = handleDelegationSub
	handlers[DelegationSettle] = handleDelegationSettle
}

func getHandler(action ActionType) handlerFn {
	h, exist := handlers[action]
	if exist {
		return h
	}
	return func(ctx *core.MessageContext, payload []byte) error {
		return errUnsupportedActionType
	}
}

type TxConverter struct {
}

func (t *TxConverter) IntrinsicGas(data []byte, to *common.Address) (uint64, error) {
	gas := params.TxValidatorGas
	return core.IntrinsicGas(gas, data)
}

func (t *TxConverter) ApplyMessage(msgCtx *core.MessageContext) ([]byte, uint64, bool, error) {
	to := msgCtx.Msg.To()
	if to == nil || *to != params.StakingModuleAddress {
		return nil, 0, false, errModuleAddress
	}
	// start from now, the message should always be accepted, no mater failed or succeed
	from := msgCtx.Msg.From()
	msgCtx.State.SetNonce(from, msgCtx.State.GetNonce(from)+1)

	var msg Message
	err := rlp.DecodeBytes(msgCtx.Msg.Data(), &msg)
	if err != nil {
		logging.Warn("tx decode failed", "txhash", msgCtx.Msg.TxHash().String(), "data", msgCtx.Msg.Data(), "err", err)
		return nil, msgCtx.InitialGas, true, nil
	}

	err = getHandler(msg.Action)(msgCtx, msg.Payload)
	if err != nil {
		logging.Warn("tx failed", "txhash", msgCtx.Msg.TxHash().String(), "action", msg.Action, "err", err)
		return nil, msgCtx.InitialGas, true, nil
	}
	return nil, msgCtx.GasUsed(), false, nil
}
