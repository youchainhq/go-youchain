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
	"bytes"
	"fmt"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/core/rawdb"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/trie"
	"time"
)

var readCHTRootFromDbTimeout = 5 * time.Second

type BlockValidator struct {
	bc BlockChainState
}

type BlockChainState interface {
	HasBlockAndState(hash common.Hash, number uint64) bool
	HasBlock(hash common.Hash, number uint64) bool
	GetHeaderByNumber(number uint64) *types.Header
	// GetAcReader returns an AcReader for reading ac node from database
	GetAcReader() rawdb.AcReader
	//
	GetChtBuilder() ChtBuilder
}

// ChtBuilder can build a temporary cht based on an existing trie and new headers
type ChtBuilder interface {
	GetCopiedCHT() (t *trie.Trie, headNum uint64)
}

func NewBlockValidator(blockChain BlockChainState) *BlockValidator {
	validator := &BlockValidator{
		bc: blockChain}
	return validator
}

func (v *BlockValidator) ValidateBody(block *types.Block) error {
	//if v.bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
	local := v.bc.GetHeaderByNumber(block.NumberU64())
	if v.bc.HasBlockAndState(block.Hash(), block.NumberU64()) && (local != nil && local.Hash() == block.Hash()) {
		return ErrKnownBlock
	}

	//block or state not exist
	if !v.bc.HasBlockAndState(block.ParentHash(), block.NumberU64()-1) {
		//block not exit
		if !v.bc.HasBlock(block.ParentHash(), block.NumberU64()-1) {
			return consensus.ErrUnknownAncestor
		}
		//state not exist
		return consensus.ErrPrunedAncestor
	}

	header := block.Header()
	if hash := types.DeriveSha(block.Transactions()); hash != header.TxHash {
		return fmt.Errorf("transaction root hash mismatch: have %x, want %x", hash, header.TxHash)
	}

	return nil
}

func (v *BlockValidator) ValidateState(block, parent *types.Block, statedb *state.StateDB, receipts types.Receipts, usedGas uint64) error {
	header := block.Header()
	if block.GasUsed() != usedGas {
		return fmt.Errorf("invalid gas used (remote: %d local: %d)", block.GasUsed(), usedGas)
	}
	// Validate the received block's bloom with the one derived from the generated receipts.
	// For valid blocks this should always validate to true.
	rbloom := types.CreateBloom(receipts)
	if rbloom != header.Bloom {
		return fmt.Errorf("invalid bloom (remote: %x  local: %x)", header.Bloom, rbloom)
	}
	// Tre receipt Trie's root (R = (Tr [[H1, R1], ... [Hn, R1]]))
	receiptSha := types.DeriveSha(receipts)
	if receiptSha != header.ReceiptHash {
		return fmt.Errorf("invalid receipt root hash (remote: %x local: %x)", header.ReceiptHash, receiptSha)
	}
	root, valRoot, stakingRoot := statedb.IntermediateRoot(true)
	if header.Root != root {
		return fmt.Errorf("invalid merkle root (remote: %x local: %x)", header.Root, root)
	}
	if header.ValRoot != valRoot {
		return fmt.Errorf("invalid validator root (remote: %x local: %x)", header.ValRoot, valRoot)
	}
	if header.StakingRoot != stakingRoot {
		return fmt.Errorf("invalid staking root (remote: %x local: %x)", header.StakingRoot, stakingRoot)
	}
	return nil
}

func (v *BlockValidator) ValidateACoCHT(headers []*types.Header, block *types.Block, index int, isNeedBuildTemp bool) error {
	var root []byte
	blockNum := block.NumberU64()
	logging.Debug("start validating cht", "num", blockNum)
	if isNeedBuildTemp {
		t, chtlastNum := v.bc.GetChtBuilder().GetCopiedCHT()
		var start uint64
		if chtlastNum > 0 {
			start = chtlastNum + 1
		}
		missingHeaders := make([]*types.Header, 0, blockNum-start)
		firstNum := headers[0].Number.Uint64()
		for j := start; j < firstNum; j++ {
			h := v.bc.GetHeaderByNumber(j)
			missingHeaders = append(missingHeaders, h)
		}
		missingHeaders = append(missingHeaders, headers[:index]...)
		logging.Debug("try buildTemporary", "chtlastNum", chtlastNum, "missingHeaders[0]", missingHeaders[0].Number, "missingHeaders[last]", missingHeaders[len(missingHeaders)-1].Number, "len(missingHeaders)", len(missingHeaders))
		stime := time.Now()
		root = BuildTemporaryCHT(t, missingHeaders).Bytes()
		logging.Debug("done buildTemporary", "elapse", time.Since(stime))
	} else {
		localChtRoot, err := v.bc.GetAcReader().ReadCHTRootWithWait(blockNum, block.ParentHash(), readCHTRootFromDbTimeout)
		if err != nil {
			logging.Warn("insertChain read chtRoot error", "blockNum", blockNum, "err", err)
			return err
		}
		root = localChtRoot
	}
	if !bytes.Equal(root, block.Header().ChtRoot) {
		logging.Error("mismatch cht root", "blockNum", blockNum, "local", hexutil.Encode(root), "header cht", hexutil.Encode(block.Header().ChtRoot))
		return consensus.ErrMismatchCHTRoot
	}
	return nil
}

// CalcGasLimit computes the gas limit of the next block after parent.
// This is miner strategy, not consensus protocol.
func CalcGasLimit(parent *types.Block) uint64 {
	// contrib = (parentGasUsed * 3 / 2) / 1024
	contrib := (parent.GasUsed() + parent.GasUsed()/2) / params.GasLimitBoundDivisor

	// decay = parentGasLimit / 1024 -1
	decay := parent.GasLimit()/params.GasLimitBoundDivisor - 1

	/*
		strategy: gasLimit of block-to-mine is set based on parent's
		gasUsed value.  if parentGasUsed > parentGasLimit * (2/3) then we
		increase it, otherwise lower it (or leave it unchanged if it's right
		at that usage) the amount increased/decreased depends on how far away
		from parentGasLimit * (2/3) parentGasUsed is.
	*/
	limit := parent.GasLimit() - decay + contrib
	logging.Trace("calcGasLimit", "decay", decay, "contrib", contrib, "limit", limit)
	if limit < params.MinGasLimit {
		limit = params.MinGasLimit
	}
	// however, if we're now below the target (TargetGasLimit) we increase the
	// limit as much as we can (parentGasLimit / 1024 -1)
	if limit < params.TargetGasLimit {
		limit = parent.GasLimit() + decay
		if limit > params.TargetGasLimit {
			limit = params.TargetGasLimit
		}
	}
	return limit
}
