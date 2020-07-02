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
	"github.com/stretchr/testify/require"
	"github.com/youchainhq/go-youchain/youdb"
	"testing"
)

func TestDetailDB(t *testing.T) {
	d := testData()
	ldb, err := youdb.NewLDBDatabase("../ignores/detail_test_ldb", 0, 0)
	require.NoError(t, err)

	ddb := NewDetailDB(ldb, true)
	ddb.WriteDetail(d)

	dec := ddb.ReadDetail(d.BlockHash)
	require.NotNil(t, dec)

	if dec.BlockHash != d.BlockHash {
		t.Errorf("blockhash, want: %s  got: %s \n", d.BlockHash.String(), dec.BlockHash.String())
	}
	if dec.BlockNumber != d.BlockNumber {
		t.Errorf("BlockNumber, want: %d  got: %d \n", d.BlockNumber, dec.BlockNumber)
	}
	if len(dec.Rewards) != len(d.Rewards) {
		t.Errorf("len(d.Rewards), want: %d  got: %d \n", len(d.Rewards), len(dec.Rewards))
	}
	if len(dec.InnerTxs) != len(d.InnerTxs) {
		t.Errorf("len(d.InnerTxs), want: %d  got: %d \n", len(d.InnerTxs), len(dec.InnerTxs))
	}
}
