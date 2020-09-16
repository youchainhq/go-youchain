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

package local

import (
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"math/big"
)

var (
	fakeRecorder DetailRecorder = &recorder{}
)

type DetailRecorder interface {
	IsWatch() bool
	Init(blockHash common.Hash, number uint64)
	AddReward(validator, coinbase common.Address, value *big.Int)
	AddInnerTx(parent common.Hash, from, to common.Address, value *big.Int, gasLimit uint64)
	Finalize() *Detail
}

func FakeRecorder() DetailRecorder {
	return fakeRecorder
}

type recorder struct {
	watch bool
	d     *Detail
}

func (r *recorder) IsWatch() bool {
	return r.watch
}

func (r *recorder) Init(blockHash common.Hash, number uint64) {
	if !r.watch {
		return
	}
	r.d = &Detail{
		Version:     1,
		BlockHash:   blockHash,
		BlockNumber: hexutil.Uint64(number),
	}
}

func (r *recorder) AddReward(validator, coinbase common.Address, value *big.Int) {
	if !r.watch {
		return
	}

	r.d.Rewards = append(r.d.Rewards, &RewardInfo{
		Validator: validator,
		Coinbase:  coinbase,
		Reward:    new(big.Int).Set(value),
	})
}

func (r *recorder) AddInnerTx(parent common.Hash, from, to common.Address, value *big.Int, gasLimit uint64) {
	if !r.watch {
		return
	}
	r.d.InnerTxs = append(r.d.InnerTxs, &InnerTx{
		ParentHash: parent,
		From:       from,
		To:         to,
		Value:      new(big.Int).Set(value),
		GasLimit:   gasLimit,
	})
}

func (r *recorder) Finalize() *Detail {
	if !r.watch {
		return nil
	}
	d := r.d
	r.d = nil
	return d
}
