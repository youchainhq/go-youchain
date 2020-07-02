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
	"github.com/youchainhq/go-youchain/rlp"
	"io"
	"math/big"
)

//go:generate gencodec -type RewardInfo -field-override rewardInfoMarshaling -out gen_reward_info_json.go
//go:generate gencodec -type InnerTx -field-override innerTxMarshaling -out gen_inner_tx_json.go

var (
	_ rlp.Encoder = &Detail{}
	_ rlp.Decoder = &Detail{}
)

type Detail struct {
	Version     uint32         `json:"version"`
	BlockHash   common.Hash    `json:"block_hash"`
	BlockNumber hexutil.Uint64 `json:"block_number"`

	// just for json
	Rewards  []*RewardInfo `json:"rewards" rlp:"-"`
	InnerTxs []*InnerTx    `json:"inner_txs" rlp:"-"`

	// just for rlp
	RewardsPayload []byte `json:"-"`
	InnerTxPayload []byte `json:"-"`
}

func (d *Detail) DecodeRLP(s *rlp.Stream) error {
	var alias = &aliasDetail{}
	if err := s.Decode(alias); err != nil {
		return err
	}
	rewards := []*RewardInfo{}
	if len(alias.RewardsPayload) > 0 {
		if err := rlp.DecodeBytes(alias.RewardsPayload, &rewards); err != nil {
			return err
		}
	}
	innertxs := []*InnerTx{}
	if len(alias.InnerTxPayload) > 0 {
		if err := rlp.DecodeBytes(alias.InnerTxPayload, &innertxs); err != nil {
			return err
		}
	}
	d.Version = alias.Version
	d.BlockNumber = alias.BlockNumber
	d.BlockHash = alias.BlockHash
	d.Rewards = rewards
	d.InnerTxs = innertxs
	return nil
}

// for rlp encode and decode
type aliasDetail Detail

func (d *Detail) EncodeRLP(w io.Writer) error {
	if len(d.Rewards) > 0 {
		rdata, err := rlp.EncodeToBytes(d.Rewards)
		if err != nil {
			return err
		}
		d.RewardsPayload = rdata
	} else {
		d.RewardsPayload = nil
	}

	if len(d.InnerTxs) > 0 {
		idata, err := rlp.EncodeToBytes(d.InnerTxs)
		if err != nil {
			return err
		}
		d.InnerTxPayload = idata
	} else {
		d.InnerTxPayload = nil
	}

	return rlp.Encode(w, (*aliasDetail)(d))
}

type RewardInfo struct {
	Validator common.Address `json:"validator"`
	Coinbase  common.Address `json:"coinbase"`
	Reward    *big.Int       `json:"reward"`
}

type rewardInfoMarshaling struct {
	Reward *hexutil.Big
}

type InnerTx struct {
	ParentHash common.Hash    `json:"parent_hash"`
	From       common.Address `json:"from"`
	To         common.Address `json:"to"`
	Value      *big.Int       `json:"value"`
	GasLimit   uint64         `json:"gas_limit"`
}

type innerTxMarshaling struct {
	Value    *hexutil.Big
	GasLimit hexutil.Uint64
}
