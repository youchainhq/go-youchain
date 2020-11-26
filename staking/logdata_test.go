// Copyright 2020 YOUCHAIN FOUNDATION LTD.
// This file is part of the go-youchain library.
//
// The go-youchain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-youchain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-youchain library. If not, see <http://www.gnu.org/licenses/>.

package staking

import (
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/rlp"
)

func TestNewSlashData(t *testing.T) {
	var (
		err           error
		round         = big.NewInt(1000)
		roundIndex    = uint32(1)
		penaltyAmount = big.NewInt(1000)
	)

	doubleSignEvidence := NewEvidence(EvidenceDoubleSign{
		Round:      round,
		RoundIndex: roundIndex,
		Signs: map[common.Hash][]byte{
			common.BigToHash(big.NewInt(1)): []byte(`sign_1`),
			common.BigToHash(big.NewInt(2)): []byte(`sign_2`),
		},
	})
	mainAddress := common.BigToAddress(big.NewInt(1000))
	records := []*SlashWithdrawRecord{
		{
			Token: big.NewInt(100),
			Record: &state.WithdrawRecord{
				Operator:         common.Address{},
				Nonce:            0,
				Validator:        mainAddress,
				Recipient:        common.Address{},
				CreationHeight:   11110,
				CompletionHeight: 11200,
				InitialBalance:   big.NewInt(1000),
				FinalBalance:     big.NewInt(100),
				Finished:         0,
				TxHash:           common.Hash{},
			},
		},
	}

	data, err := NewSlashData(EventTypeDoubleSign, mainAddress, penaltyAmount, records, &doubleSignEvidence)
	assert.NoError(t, err)
	hash := data.Hash()
	bytes, err := rlp.EncodeToBytes(data)
	assert.NoError(t, err)

	data2 := SlashData{}
	err = rlp.DecodeBytes(bytes, &data2)
	assert.NoError(t, err)
	assert.Equal(t, data.Total, data2.Total)
	assert.Equal(t, data2.Hash().String(), hash.String())
	evd := data2.Evidence.(*Evidence)

	dbs := EvidenceDoubleSign{}
	err = rlp.DecodeBytes(evd.Data, &dbs)
	assert.NoError(t, err)
	assert.Equal(t, round, dbs.Round)
	assert.Equal(t, roundIndex, dbs.RoundIndex)
	assert.Equal(t, 2, len(dbs.Signs))
	assert.Equal(t, mainAddress, data2.Records[0].Record.Validator)
}

func TestSlashDataV5(t *testing.T) {
	data := &SlashDataV5{
		Type:         EventTypeInactive,
		MainAddress:  common.Address{0x11, 0x22},
		Total:        nil,
		FromWithdraw: nil,
		FromDeposit:  nil,
		Evidence:     nil,
	}
	bs, err := rlp.EncodeToBytes(data)
	require.NoError(t, err)
	data2 := &SlashDataV5{}
	err = rlp.DecodeBytes(bs, data2)
	require.NoError(t, err)
	require.Equal(t, data.Type, data2.Type)
	bs2, err2 := rlp.EncodeToBytes(data)
	require.NoError(t, err2)
	require.Equal(t, bs, bs2)
}
