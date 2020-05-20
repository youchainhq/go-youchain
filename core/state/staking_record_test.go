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

package state

import (
	"bytes"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/rlp"
)

func TestPendingRelationship(t *testing.T) {
	var ds, vs []common.Address
	for i := 0; i < 5; i++ {
		ds = append(ds, common.BytesToAddress([]byte{byte(i), 1}))
		vs = append(vs, common.BytesToAddress([]byte{byte(i), 0x10}))
	}
	p := newPendingRelationship()
	require.EqualValues(t, 0, p.DelegatorPendingCount(ds[0]))
	require.EqualValues(t, false, p.Exist(ds[0], vs[0]))

	//add first one
	require.EqualValues(t, true, p.Add(ds[1], vs[1]))
	require.EqualValues(t, true, p.Exist(ds[1], vs[1]))
	require.EqualValues(t, 1, p.ValidatorPendingCount(vs[1]))

	//append to last
	require.EqualValues(t, true, p.Add(ds[4], vs[4]))

	//insert to first
	require.EqualValues(t, true, p.Add(ds[0], vs[0]))
	//insert to middle
	require.EqualValues(t, true, p.Add(ds[2], vs[2]))
	require.EqualValues(t, true, p.Add(ds[3], vs[3]))

	//do not add if exist
	require.EqualValues(t, false, p.Add(ds[4], vs[4]))
	require.EqualValues(t, false, p.Add(ds[1], vs[1]))

	// check count
	require.EqualValues(t, true, p.Add(ds[2], vs[3]))
	require.EqualValues(t, 2, p.DelegatorPendingCount(ds[2]))
	require.EqualValues(t, 2, p.ValidatorPendingCount(vs[3]))

	// check order
	for i := 1; i < 5; i++ {
		require.Less(t, bytes.Compare(p.r[i-1][:], p.r[i][:]), 0)
	}

	// encode and decode
	bs, err := rlp.EncodeToBytes(p)
	require.NoError(t, err)
	require.Less(t, 6*2*common.AddressLength, len(bs))

	p2 := newPendingRelationship()
	err = rlp.DecodeBytes(bs, p2)
	require.NoError(t, err)
	require.EqualValues(t, 2, p2.DelegatorPendingCount(ds[2]))
	require.EqualValues(t, 2, p2.ValidatorPendingCount(vs[3]))
	for i := 0; i < 6; i++ {
		require.EqualValues(t, p.r[i], p2.r[i])
	}
}

func TestPendingRelationship_DeepCopy(t *testing.T) {
	p := newPendingRelationship()
	var ds, vs []common.Address
	for i := 0; i < 5; i++ {
		ds = append(ds, common.BytesToAddress([]byte{byte(i), 1}))
		vs = append(vs, common.BytesToAddress([]byte{byte(i), 0x10}))
	}
	for i := 0; i < 4; i++ {
		p.Add(ds[i], vs[i])
	}
	p2 := p.DeepCopy()
	p.Add(ds[4], vs[4])

	require.EqualValues(t, 4, len(p2.r))
	for i := 0; i < 4; i++ {
		require.EqualValues(t, true, p2.Exist(ds[i], vs[i]))
	}
	require.EqualValues(t, false, p2.Exist(ds[4], vs[4]))
}

func TestStakingRecord_DeepCopy(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	hs := make([]common.Hash, 3, 4)
	for i := 0; i < 3; i++ {
		rand.Read(hs[i][:])
	}
	sr := &stakingRecord{
		record: Record{
			FinalValue: new(big.Int).SetInt64(20200420),
			TxHashes:   hs,
		},
	}
	cpy := sr.DeepCopy()
	//change sr
	sr.record.FinalValue.SetInt64(20200421)
	h := common.Hash{}
	rand.Read(h[:])
	sr.record.TxHashes = append(sr.record.TxHashes, h)

	require.EqualValues(t, 3, len(cpy.record.TxHashes))
	for i := range cpy.record.TxHashes {
		if cpy.record.TxHashes[i] != sr.record.TxHashes[i] {
			t.Error("index ", i)
		}
	}
	require.EqualValues(t, 20200420, cpy.record.FinalValue.Int64())
	require.EqualValues(t, 20200421, sr.record.FinalValue.Int64())
}
