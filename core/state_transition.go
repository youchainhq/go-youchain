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

package core

import (
	"errors"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/vm"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"math"
	"math/big"
)

var (
	errInsufficientBalanceForGas = errors.New("insufficient balance to pay for gas")
	ErrCancelled                 = errors.New("cancelled")
)

var _ TxConverter = &DefaultConverter{}

type DefaultConverter struct {
}

func (d *DefaultConverter) IntrinsicGas(data []byte, to *common.Address) (uint64, error) {
	// Set the starting gas for the raw transaction
	var gas uint64
	switch {
	case to == nil:
		gas = params.TxGasContractCreation
	default:
		gas = params.TxGas
	}
	return IntrinsicGas(gas, data)
}

func IntrinsicGas(basicGas uint64, data []byte) (uint64, error) {
	gas := basicGas
	// Bump the required gas by the amount of transactional data
	if len(data) > 0 {
		// Zero and non-zero bytes are priced differently
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		// Make sure we don't exceed uint64 for all data combinations
		if (math.MaxUint64-gas)/params.TxDataNonZeroGas < nz {
			return 0, vm.ErrOutOfGas
		}
		gas += nz * params.TxDataNonZeroGas

		z := uint64(len(data)) - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, vm.ErrOutOfGas
		}
		gas += z * params.TxDataZeroGas
	}
	return gas, nil
}

func (d *DefaultConverter) ApplyMessage(msgCtx *MessageContext) (ret []byte, usedGas uint64, failed bool, err error) {
	// Create a new context to be used in the EVM environment
	evmctx := NewEVMContext(msgCtx.Msg, msgCtx.Header, msgCtx.Chain, msgCtx.Coinbase, msgCtx.Recorder)
	// Create a new environment which holds all relevant information about the transaction and calling mechanisms.
	evm := vm.NewEVM(evmctx, msgCtx.State, msgCtx.Cfg)
	//handle cancel
	ctx, cancel, isWithCancel := msgCtx.Cfg.CancelContext()
	if isWithCancel {
		defer cancel()
		go func() {
			<-ctx.Done()
			evm.Cancel()
		}()
		defer func() {
			if evm.Cancelled() {
				err = ErrCancelled
			}
		}()
	}

	return newStateTransition(msgCtx, evm).TransitionDb()
}

type StateTransition struct {
	*MessageContext
	value *big.Int
	data  []byte
	evm   *vm.EVM
}

// NewStateTransition initialises and returns a new state transition object.
func newStateTransition(msgCtx *MessageContext, evm *vm.EVM) *StateTransition {
	return &StateTransition{
		MessageContext: msgCtx,
		evm:            evm,
		value:          msgCtx.Msg.Value(),
		data:           msgCtx.Msg.Data(),
	}
}

// to returns the recipient of the message.
func (st *StateTransition) to() common.Address {
	if st.Msg == nil || st.Msg.To() == nil /* contract creation */ {
		return common.Address{}
	}
	return *st.Msg.To()
}

// TransitionDb will transition the state by applying the current message and
// returning the result including the used gas. It returns an error if failed.
// An error indicates a consensus issue.
// note: add ignoreNonce for preCheck
func (st *StateTransition) TransitionDb() (ret []byte, usedGas uint64, failed bool, err error) {
	msg := st.Msg
	sender := vm.AccountRef(msg.From())
	contractCreation := msg.To() == nil

	defer func() {
		logFn := logging.Trace
		if err != nil {
			logFn = logging.Error
		}
		logFn("transactionDB", "tx", msg.TxHash().String(), "from", msg.From().String(), "to", st.to().String(), "usedGas", usedGas, "failed", failed, "err", err)
	}()

	var (
		evm = st.evm
		// vm errors do not effect consensus and are therefor not assigned to err, except for insufficient balance error.
		vmerr error
	)

	if contractCreation {
		ret, _, st.AvailableGas, vmerr = evm.Create(sender, st.data, st.AvailableGas, st.value)
	} else {
		// Increment the nonce for the next transaction
		st.State.SetNonce(msg.From(), st.State.GetNonce(sender.Address())+1)
		ret, st.AvailableGas, vmerr = evm.Call(sender, st.to(), st.data, st.AvailableGas, st.value)
	}
	if vmerr != nil {
		logging.Debug("VM returned with error", "err", vmerr)
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		if vmerr == vm.ErrInsufficientBalance {
			return nil, 0, false, vmerr
		}
	}

	return ret, st.GasUsed(), vmerr != nil, err
}
