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

package state

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/youdb"
)

func TestStateVal(t *testing.T) {
	db := youdb.NewMemDatabase()
	st, err := New(common.Hash{}, common.Hash{}, common.Hash{}, NewDatabase(db))
	assert.NoError(t, err)
	st.AddBalance(common.BigToAddress(big.NewInt(10000)), big.NewInt(100000))
	st.AddBalance(common.BigToAddress(big.NewInt(10001)), big.NewInt(100000))
	st.AddBalance(common.BigToAddress(big.NewInt(10002)), big.NewInt(100000))
	root1, valRoot1, _ := st.IntermediateRoot(true)
	fmt.Println("init", "root", root1.String(), "valRoot", valRoot1.String())

	// create
	snap := st.Snapshot()
	logging.Info("make snapshot", "id", snap)

	logging.Info("create 10 validators")
	for i := 0; i < 3; i++ {
		valAddr := common.BigToAddress(big.NewInt(int64(i)))
		valKey, _ := crypto.GenerateKey()
		valPub := crypto.CompressPubkey(&valKey.PublicKey)
		st.CreateValidator(valAddr.String(), valAddr, valAddr, params.RoleChancellor, valPub, valPub, big.NewInt(1000), big.NewInt(1000), params.AcceptDelegation, 2000, 1000, params.ValidatorOnline)
	}

	logging.Info("revert to snapshot", "snap", snap)
	st.RevertToSnapshot(snap)

	{
		root, valRoot, _ := st.IntermediateRoot(true)
		logging.Info("after add new validator", "root", root.String(), "valRoot", valRoot.String())
	}

	snap = st.Snapshot()
	for i := 20; i < 30; i++ {
		valAddr := common.BigToAddress(big.NewInt(int64(i)))
		valKey, _ := crypto.GenerateKey()
		valPub := crypto.CompressPubkey(&valKey.PublicKey)
		st.CreateValidator(valAddr.String(), valAddr, valAddr, params.RoleChancellor, valPub, valPub, big.NewInt(1000), big.NewInt(1000), params.AcceptDelegation, 2000, 1000, params.ValidatorOnline)
	}
	{
		root, valRoot, _ := st.IntermediateRoot(true)
		fmt.Println("after revert", snap, "root", root.String(), "valRoot", valRoot.String())
	}
}
