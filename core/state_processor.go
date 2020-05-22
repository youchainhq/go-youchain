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
	"fmt"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/core/vm"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"math/big"
	"runtime"
	"sync"
)

var (
	errInvalidGasRewards = errors.New("invalid gas rewards")
)

var _ Processor = &StateProcessor{}

type BlockHookFn func(chain vm.ChainReader, header *types.Header, txs []*types.Transaction, state *state.StateDB, seal bool) (*types.Receipt, []byte, error)
type hookFunc struct {
	Name string
	Run  BlockHookFn
}

type StateProcessor struct {
	bc     *BlockChain
	engine consensus.Engine // Consensus engine used for block rewards

	txConverters  map[common.Address]TxConverter // converter map: modelAddress->converter
	endBlockHooks []hookFunc

	defaultConverter TxConverter
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		bc:           bc,
		engine:       engine,
		txConverters: make(map[common.Address]TxConverter),

		defaultConverter: &DefaultConverter{},
	}
}

func (p *StateProcessor) Process(yp *params.YouParams, block *types.Block, statedb *state.StateDB, lcfg vm.LocalConfig) (types.Receipts, []*types.Log, uint64, error) {
	if yp == nil {
		return nil, nil, 0, errors.New("no YouParams")
	}
	var (
		receipts   types.Receipts
		allLogs    []*types.Log
		header     = block.Header()
		usedGas    = new(uint64)
		gasRewards = new(big.Int)
		gp         = new(GasPool).AddGas(block.GasLimit())
	)

	cfg := CombineVMConfig(yp, lcfg)
	signer := types.MakeSigner(header.Number)
	ProcessSenders(block.Transactions(), signer)

	for i, tx := range block.Transactions() {
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		receipt, _, err := p.ApplyTransaction(tx, signer, statedb, p.bc, header, nil, usedGas, gasRewards, gp, cfg)
		if err != nil {
			return nil, nil, 0, err
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}

	// verify gas rewards
	if gasRewards.Cmp(header.GasRewards) != 0 {
		return nil, nil, 0, errInvalidGasRewards
	}

	logging.Info("process block", "number", header.Number, "txs", block.Transactions().Len(), "usedGas", usedGas, "hUsedGas", header.GasUsed, "gasRewards", gasRewards, "hGasRewards", header.GasRewards)

	extendReceipts, _, _ := p.EndBlock(p.bc, header, block.Transactions(), statedb, false)
	for _, receipt := range extendReceipts {
		if receipt != nil {
			receipts = append(receipts, receipt)
			allLogs = append(allLogs, receipt.Logs...)
		}
	}
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), receipts)

	return receipts, allLogs, *usedGas, nil
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func (p *StateProcessor) ApplyTransaction(tx *types.Transaction, signer types.Signer, statedb *state.StateDB,
	bc ChainContext, header *types.Header, author *common.Address, usedGas *uint64, gasRewards *big.Int, gp *GasPool, cfg *vm.Config) (*types.Receipt, uint64, error) {
	msg, err := tx.AsMessage(signer)
	if err != nil {
		return nil, 0, err
	}

	metricsTxExecute.Mark(1)

	_, gas, failed, err := p.ApplyMessageEntry(msg, statedb, bc, header, author, gp, cfg)
	if err != nil {
		metricsTxExeFailed.Mark(1)
		return nil, 0, err
	}
	logging.Trace("apply transaction Finalise", "tx", tx.Hash().String(), "gas", gas, "failed", failed, "err", err)
	statedb.Finalise(true)
	*usedGas += gas
	gasRewards.Add(gasRewards, new(big.Int).Mul(tx.GasPrice(), new(big.Int).SetUint64(gas)))

	receipt := types.NewReceipt([]byte{}, failed, *usedGas)
	receipt.TxHash = msg.TxHash()
	receipt.GasUsed = gas
	// if the transaction created a contract, store the creation address in the receipt.
	if tx.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(msg.From(), msg.Nonce())
	}
	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(msg.TxHash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = statedb.BlockHash()
	receipt.BlockNumber = header.Number
	receipt.TransactionIndex = uint(statedb.TxIndex())

	//r, _ := receipt.MarshalJSON()
	//log.Trace("receipt", string(r))
	metricsTxExeSuccess.Mark(1)
	return receipt, gas, nil
}

func ProcessSenders(txs []*types.Transaction, signer types.Signer) {
	if len(txs) == 0 {
		return
	}
	max := runtime.NumCPU()
	if len(txs) < max {
		return
	}
	per := len(txs) / max

	wg := sync.WaitGroup{}
	for i := 0; i <= max; i++ {
		if len(txs) == 0 {
			break
		}
		wg.Add(1)
		var jobs []*types.Transaction
		if len(txs) > per {
			jobs = txs[0:per]
			txs = txs[per:]
		} else {
			jobs = txs[:]
		}
		go func(jobs []*types.Transaction) {
			defer wg.Done()
			for _, tx := range jobs {
				_, _ = types.Sender(signer, tx)
			}
		}(jobs)
	}
	wg.Wait()
}

// ApplyMessageEntry is the common entry for applying a message
// There are some common steps to do here.
func (p *StateProcessor) ApplyMessageEntry(msg Message, statedb *state.StateDB,
	bc ChainContext, header *types.Header, author *common.Address, gp *GasPool, cfg *vm.Config) ([]byte, uint64, bool, error) {
	// If we don't have an explicit author (i.e. not mining), extract from the header
	var coinbase common.Address
	if author == nil {
		coinbase = header.Coinbase // Ignore error, we're past header validation
	} else {
		coinbase = *author
	}
	msgCtx := NewMsgContext(msg, statedb, bc, header, coinbase, gp, cfg)
	// First, do pre check, checks the nonce and buy the supplied gas
	if err := msgCtx.preCheck(); err != nil {
		return nil, 0, false, err
	}
	// Then, consumes the intrinsic gas
	c := p.GetConverter(msg.To())
	intrinsicGas, err := c.IntrinsicGas(msg.Data(), msg.To())
	if err != nil {
		return nil, 0, false, err
	}
	logging.Trace("tx", "from", msg.From().String(), "tx", msg.TxHash().String(), "intrinsicGas", intrinsicGas)
	if err = msgCtx.UseGas(intrinsicGas); err != nil {
		return nil, 0, false, err
	}

	// Finally, call the ApplyMessage for specific handle.
	ret, gasUsed, failed, err := c.ApplyMessage(msgCtx)
	//refund gas
	msgCtx.refundGas()
	return ret, gasUsed, failed, err
}

// AddTxConverter adds a transaction converter for a given model address.
// This method should be called on the initialization stage and is NOT thread safe.
func (p *StateProcessor) AddTxConverter(modelAddr common.Address, converter TxConverter) {
	if _, exist := p.txConverters[modelAddr]; exist {
		panic(fmt.Sprintf("converter exist for model address %s", modelAddr.String()))
	}
	p.txConverters[modelAddr] = converter
}

func (p *StateProcessor) GetConverter(msgToAddr *common.Address) TxConverter {
	if msgToAddr == nil {
		return p.defaultConverter
	}
	if c, ok := p.txConverters[*msgToAddr]; ok {
		return c
	}
	return p.defaultConverter
}

func (p *StateProcessor) AddEndBlockHook(name string, fn BlockHookFn) {
	p.endBlockHooks = append(p.endBlockHooks, hookFunc{Name: name, Run: fn})
}

func (p *StateProcessor) EndBlock(chain vm.ChainReader, header *types.Header, txs []*types.Transaction, state *state.StateDB, isSeal bool) ([]*types.Receipt, [][]byte, []error) {
	count := len(p.endBlockHooks)
	if count == 0 {
		return nil, nil, nil
	}
	var data = make([][]byte, count)
	var errs = make([]error, count)
	var recs = make([]*types.Receipt, count)
	for i, hook := range p.endBlockHooks {
		recs[i], data[i], errs[i] = hook.Run(chain, header, txs, state, isSeal)
	}
	logging.Info("after end block", "header", header.Number, "slashdata", hexutil.Encode(header.SlashData), "gasUsed", header.GasUsed, "gasRewards", header.GasRewards, "subsidy", header.Subsidy, "isSeal", isSeal)
	return recs, data, errs
}
