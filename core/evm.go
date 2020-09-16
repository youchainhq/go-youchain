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
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/core/vm"
	"github.com/youchainhq/go-youchain/local"
	"github.com/youchainhq/go-youchain/params"
	"math/big"
)

// ChainContext supports retrieving headers and consensus parameters from the
// current blockchain to be used during transaction processing.
type ChainContext interface {
	// VersionForRound retrieves the YOUChain protocol parameters for the specific round
	VersionForRound(round uint64) (*params.YouParams, error)

	// GetHeader returns the hash corresponding to their hash.
	GetHeader(common.Hash, uint64) *types.Header
}

// NewEVMContext creates a new context for use in the EVM.
func NewEVMContext(msg Message, header *types.Header, chain ChainContext, author common.Address, recorder local.DetailRecorder) vm.Context {
	return vm.Context{
		CanTransfer:   CanTransfer,
		Transfer:      Transfer,
		GetHash:       GetHashFn(header, chain),
		Origin:        msg.From(),
		To:            msg.To(),
		TxHash:        msg.TxHash(),
		Coinbase:      author,
		BlockNumber:   new(big.Int).Set(header.Number),
		Time:          new(big.Int).SetUint64(header.Time),
		GasLimit:      header.GasLimit,
		GasPrice:      new(big.Int).Set(msg.GasPrice()),
		LocalRecorder: recorder,
	}
}

// GetHashFn returns a GetHashFunc which retrieves header hashes by number
func GetHashFn(ref *types.Header, chain ChainContext) func(n uint64) common.Hash {
	var cache map[uint64]common.Hash

	return func(n uint64) common.Hash {
		// If there's no hash cache yet, make one
		if cache == nil {
			cache = map[uint64]common.Hash{
				ref.Number.Uint64() - 1: ref.ParentHash,
			}
		}
		// Try to fulfill the request from the cache
		if hash, ok := cache[n]; ok {
			return hash
		}
		// Not cached, iterate the blocks and cache the hashes
		for header := chain.GetHeader(ref.ParentHash, ref.Number.Uint64()-1); header != nil; header = chain.GetHeader(header.ParentHash, header.Number.Uint64()-1) {
			cache[header.Number.Uint64()-1] = header.ParentHash
			if n == header.Number.Uint64()-1 {
				return header.ParentHash
			}
		}
		return common.Hash{}
	}
}

// CanTransfer checks whether there are enough funds in the address' account to make a transfer.
// This does not take the necessary gas in to account to make the transfer valid.
func CanTransfer(db vm.StateDB, addr common.Address, amount *big.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0
}

// Transfer subtracts amount from sender and adds amount to recipient using the given Db
func Transfer(db vm.StateDB, sender, recipient common.Address, amount *big.Int) {
	db.SubBalance(sender, amount)
	db.AddBalance(recipient, amount)
}

func CombineVMConfig(yp *params.YouParams, lcfg vm.LocalConfig) *vm.Config {
	cfg := vm.Config{
		RuntimeConfig: vm.RuntimeConfig{CurrYouParams: yp, JumpTable: vm.GetJumpTable(yp.EVMVersion)},
		LocalConfig:   lcfg,
	}
	return &cfg
}

func PrepareVMConfig(ctx ChainContext, round uint64, lcfg vm.LocalConfig) (*vm.Config, error) {
	yp, err := ctx.VersionForRound(round)
	if err != nil {
		return &vm.Config{}, err
	}
	return CombineVMConfig(yp, lcfg), nil
}
