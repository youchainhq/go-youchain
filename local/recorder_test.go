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
	"github.com/youchainhq/go-youchain/youdb"
	"math/big"
	"testing"
)

func TestRecorder(t *testing.T) {
	ldb, err := youdb.NewLDBDatabase("../ignores/detail_test_recorder", 0, 0)
	require.NoError(t, err)
	ddb := NewDetailDB(ldb, true)
	recorder := ddb.NewRecorder()
	recorder.Init(common.HexToHash("0x214f762a575b1442eddeb6bae3f287a8cff20adc13827f2defce02df837e3066"), 143)
	value := new(big.Int).SetUint64(12300000000000000)
	recorder.AddReward(common.HexToAddress("0xbe635E5a8D2552160c26221ADC1c8A58730E388B"), common.HexToAddress("0xbe635E5a8D2552160c26221ADC1c8A58730E388B"), value)

	d := recorder.Finalize()
	ddb.WriteDetail(d)

	dec := ddb.ReadDetail(common.HexToHash("0x214f762a575b1442eddeb6bae3f287a8cff20adc13827f2defce02df837e3066"))

	require.Equal(t, d.Rewards[0].Validator.String(), dec.Rewards[0].Validator.String())
	require.Equal(t, value.Uint64(), dec.Rewards[0].Reward.Uint64())
	bs, err := json.Marshal(dec)
	require.NoError(t, err)
	fmt.Println(string(bs))
}
