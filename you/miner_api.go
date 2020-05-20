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
	"github.com/youchainhq/go-youchain/common/hexutil"
	"math/big"
)

type PrivateMinerApi struct {
	c *YouChain
}

func NewPrivateMinerApi(c *YouChain) *PrivateMinerApi {
	return &PrivateMinerApi{c}
}

// Start starts the miner and engine for mining.
// If mining is already running, this method just do nothing.
func (api *PrivateMinerApi) Start() error {
	return api.c.StartMining()
}

func (api *PrivateMinerApi) Stop() {
	api.c.miner.Stop()
}

// Mining returns an indication if this node is currently mining.
func (api *PrivateMinerApi) Mining() bool {
	return api.c.miner.Mining()
}

// SetExtra sets the extra data string that is included when this miner mines a block.
func (api *PrivateMinerApi) SetExtra(extra string) (bool, error) {
	if err := api.c.miner.SetExtra([]byte(extra)); err != nil {
		return false, err
	}
	return true, nil
}

// SetGasPrice sets the minimum accepted gas price for the miner.
func (api *PrivateMinerApi) SetGasPrice(gasPrice hexutil.Big) bool {
	api.c.TxPool().SetGasPrice((*big.Int)(&gasPrice))
	return true
}
