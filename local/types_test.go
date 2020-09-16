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
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/rlp"
	"math/big"
	"testing"
)

func TestDetail_EncodeRLP(t *testing.T) {
	d := testData()

	encodeDecode(t, d)
	encodeDecodeJson(t, d)
	d.InnerTxs = nil
	encodeDecode(t, d)
	encodeDecodeJson(t, d)
	d.Rewards = nil
	encodeDecode(t, d)
	encodeDecodeJson(t, d)
}

func encodeDecode(t *testing.T, d *Detail) {
	bs, err := rlp.EncodeToBytes(d)
	require.NoError(t, err)
	var dec Detail
	err = rlp.DecodeBytes(bs, &dec)
	require.NoError(t, err)
	if dec.BlockHash != d.BlockHash {
		t.Errorf("blockhash, want: %s  got: %s \n", d.BlockHash.String(), dec.BlockHash.String())
	}
	if dec.BlockNumber != d.BlockNumber {
		t.Errorf("BlockNumber, want: %d  got: %d \n", d.BlockNumber, dec.BlockNumber)
	}
	if len(dec.Rewards) != len(d.Rewards) {
		t.Errorf("len(d.Rewards), want: %d  got: %d \n", len(d.Rewards), len(dec.Rewards))
	}
	if len(d.Rewards) > 0 {
		if dec.Rewards[0].Reward.Cmp(d.Rewards[0].Reward) != 0 {
			t.Errorf("Reward value mismatch, want: %d  got: %d \n", d.Rewards[0].Reward, dec.Rewards[0].Reward)
		}
	}
	if len(dec.InnerTxs) != len(d.InnerTxs) {
		t.Errorf("len(d.InnerTxs), want: %d  got: %d \n", len(d.InnerTxs), len(dec.InnerTxs))
	}
	if len(d.InnerTxs) > 0 {
		if dec.InnerTxs[0].Value.Cmp(d.InnerTxs[0].Value) != 0 {
			t.Errorf("InnerTx value mismatch, want: %d  got: %d \n", d.InnerTxs[0].Value, dec.InnerTxs[0].Value)
		}
	}
}

func encodeDecodeJson(t *testing.T, d *Detail) {
	bs, err := json.Marshal(d)
	require.NoError(t, err)
	fmt.Println(string(bs))
	var dec Detail
	err = json.Unmarshal(bs, &dec)
	require.NoError(t, err)
	if dec.BlockHash != d.BlockHash {
		t.Errorf("blockhash, want: %s  got: %s \n", d.BlockHash.String(), dec.BlockHash.String())
	}
	if dec.BlockNumber != d.BlockNumber {
		t.Errorf("BlockNumber, want: %d  got: %d \n", d.BlockNumber, dec.BlockNumber)
	}
	if len(dec.Rewards) != len(d.Rewards) {
		t.Errorf("len(d.Rewards), want: %d  got: %d \n", len(d.Rewards), len(dec.Rewards))
	}
	if len(d.Rewards) > 0 {
		if dec.Rewards[0].Reward.Cmp(d.Rewards[0].Reward) != 0 {
			t.Errorf("Reward value mismatch, want: %d  got: %d \n", d.Rewards[0].Reward, dec.Rewards[0].Reward)
		}
	}
	if len(dec.InnerTxs) != len(d.InnerTxs) {
		t.Errorf("len(d.InnerTxs), want: %d  got: %d \n", len(d.InnerTxs), len(dec.InnerTxs))
	}
	if len(d.InnerTxs) > 0 {
		if dec.InnerTxs[0].Value.Cmp(d.InnerTxs[0].Value) != 0 {
			t.Errorf("InnerTx value mismatch, want: %d  got: %d \n", d.InnerTxs[0].Value, dec.InnerTxs[0].Value)
		}
	}
}

func testData() *Detail {
	d := &Detail{
		Version:     1,
		BlockHash:   common.HexToHash("0x214f762a575b1442eddeb6bae3f287a8cff20adc13827f2defce02df837e3030"),
		BlockNumber: 123,
		Rewards: []*RewardInfo{
			{common.HexToAddress("0xbe635E5a8D2552160c26221ADC1c8A58730E388B"), common.HexToAddress("0xbe635E5a8D2552160c26221ADC1c8A58730E388B"), new(big.Int).SetUint64(1200000000000000000)},
			{common.HexToAddress("0xbe635E5a8D2552160c26221ADC1c8A58730E388B"), common.HexToAddress("0x96239A822971d27f2E96DA01864185F676D916Ae"), new(big.Int).SetUint64(800000000000000000)},
		},
		InnerTxs: []*InnerTx{
			{common.HexToHash("0x8aa050146fca082f9d856757c114e8e175f988eaf3b0d733c5e10f1672e1d53f"),
				common.HexToAddress("0xbe635E5a8D2552160c26221ADC1c8A58730E388B"),
				common.HexToAddress("0x96239A822971d27f2E96DA01864185F676D916Ae"),
				new(big.Int).SetUint64(800000000000000000),
				100000,
			},
		},
		RewardsPayload: nil,
		InnerTxPayload: nil,
	}
	return d
}
