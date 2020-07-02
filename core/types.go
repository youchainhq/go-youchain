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
	"math/big"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/core/vm"
	"github.com/youchainhq/go-youchain/local"
	"github.com/youchainhq/go-youchain/params"
)

// Validator is an interface which defines the standard for block validation. It
// is only responsible for validating block contents, as the header validation is
// done by the specific consensus engines.
//
type Validator interface {
	// ValidateBody validates the given block's content.
	ValidateBody(block *types.Block) error

	// ValidateState validates the given statedb and optionally the receipts and
	// gas used.
	ValidateState(block, parent *types.Block, statedb *state.StateDB, receipts types.Receipts, usedGas uint64) error

	// ValidateACoCHT validates the given block's ac node.
	// Before calling this function, the caller must check if is needed to do this validate.
	ValidateACoCHT(headers []*types.Header, block *types.Block, index int, isNeedBuildTemp bool) error
}

// Processor is an interface for processing blocks using a given initial state.
//
//Processor provides several methods on different level, from common to detail is as follow:
//`Process` is the entry for replaying a whole block;
//`ApplyTransaction` is the entry for replaying a specific transaction;
//`ApplyMessageEntry` is the entry for applying a message (derives from a tx), this may be called independently ON LOCAL for test-case or contract call or estimating gas.
type Processor interface {
	IRouter
	// Process takes the block to be processed and the statedb upon which the
	// initial state is based. It should return the receipts generated, amount
	// of gas used in the process and return an error if any of the internal rules
	// failed.
	Process(yp *params.YouParams, block *types.Block, statedb *state.StateDB, cfg vm.LocalConfig, recorder local.DetailRecorder) (*types.ProcessResult, error)
	// ApplyTransaction attempts to apply a transaction to the given state database
	// and uses the input parameters for its environment. It returns the receipt
	// for the transaction, gas used and an error if the transaction failed,
	// indicating the block was invalid.
	ApplyTransaction(tx *types.Transaction, signer types.Signer, statedb *state.StateDB, bc ChainContext, header *types.Header, author *common.Address, usedGas *uint64, gasRewards *big.Int, gp *GasPool, cfg *vm.Config, recorder local.DetailRecorder) (*types.Receipt, uint64, error)
	// ApplyMessage computes the new state by applying the given message
	// against the old state within the environment.
	//
	// ApplyMessage returns:
	// the bytes returned by any TxConverter execution (if it took place),
	// the gas used (which includes gas refunds) ,
	// a flag indicates whether the message is failed
	// but (with err == nil) would be accepted within a block,
	// and an error if it failed. An error always indicates a core error meaning
	// that the message would always fail for that particular state and would
	// never be accepted within a block.
	ApplyMessageEntry(msg Message, statedb *state.StateDB, bc ChainContext, header *types.Header, author *common.Address, gp *GasPool, cfg *vm.Config, recorder local.DetailRecorder) ([]byte, uint64, bool, error)

	// EndBlock executes some extended logic registered by other modules
	EndBlock(chain vm.ChainReader, header *types.Header, txs []*types.Transaction, state *state.StateDB, isSeal bool, recorder local.DetailRecorder) ([]*types.Receipt, [][]byte, []error)
}

// IRouter is an interface for routing a transaction to a state converter.
// It also provides extended EndBlock logic.
type IRouter interface {
	AddEndBlockHook(name string, fn BlockHookFn)
	AddTxConverter(modelAddr common.Address, converter TxConverter)
	GetConverter(msgToAddr *common.Address) TxConverter
}

// TxConverter is an interface for converting the state with given transactions.
type TxConverter interface {
	// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
	IntrinsicGas(data []byte, to *common.Address) (uint64, error)
	// ApplyMessage computes the new state by applying the given message
	// against the state database.
	// ApplyMessage returns the bytes returned by any execution (if it took place),
	// the gas used (which includes gas refunds) and an error if it failed. An error always
	// indicates a core error meaning that the message would always fail for that particular
	// state and would never be accepted within a block.
	//
	// NOTE: If the message will be accepted, the converter MUST increase the sender nonce!
	ApplyMessage(msgCtx *MessageContext) ([]byte, uint64, bool, error)
}
