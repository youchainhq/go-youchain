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

package you

import (
	"math/big"

	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/you/gasprice"
)

var DefaultConfig = Config{
	NetworkId:       1,
	DatabaseCache:   768,
	TrieCache:       256,
	DatabaseHandles: 256,

	MinerGasPrice: new(big.Int).SetUint64(params.DefaultMinGasPrice),

	TxPool: core.DefaultTxPoolConfig,
	GPO: gasprice.Config{
		Blocks:     20,
		Percentile: 60,
	},
}

func NewDefaultConfig() Config {
	cfg := &DefaultConfig
	return *cfg
}

//go:generate gencodec -type Config -field-override configMarshaling -formats toml -out gen_config.go
type Config struct {
	// The genesis block, which is inserted if the database is empty.
	// If nil, the main net block is used.
	Genesis *core.Genesis `toml:",omitempty"`

	NetworkId uint64

	//DB
	DatabaseCache   int
	DatabaseHandles int
	TrieCache       int

	MinerGasPrice *big.Int

	// Transaction pool options
	TxPool core.TxPoolConfig

	// Gas Price Oracle options
	GPO gasprice.Config

	// RPCGasCap is the global gas cap for eth-call variants.
	RPCGasCap *big.Int `toml:",omitempty"`
}
