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

package state

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/youdb"
)

func newTestLDB() (*youdb.LDBDatabase, func()) {
	db, err := youdb.NewLDBDatabase("./youdb_test", 256, 256)
	if err != nil {
		panic("failed to create test database: " + err.Error())
	}

	return db, func() {
		db.Close()
	}
}

// Tests that updating a state trie does not leak any database writes prior to
// actually committing the state.
func TestUpdateLeaks(t *testing.T) {
	// Create an empty state database
	db := youdb.NewMemDatabase()

	state, _ := New(common.Hash{}, common.Hash{}, common.Hash{}, NewDatabase(db))

	// Update it with some accounts
	for i := byte(0); i < 255; i++ {
		addr := common.BytesToAddress([]byte{i})
		state.AddBalance(addr, big.NewInt(int64(11*i)))
		state.SetNonce(addr, uint64(42*i))
		if i%2 == 0 {
			state.SetState(addr, common.BytesToHash([]byte{i, i, i}), common.BytesToHash([]byte{i, i, i, i}))
		}
		state.IntermediateRoot(false)
	}

	////real commit
	//root, _ := state.Commit(false)
	//state.Database().TrieDB().Commit(root, false)

	// Ensure that no data was leaked into the database
	for _, key := range db.Keys() {
		value, _ := db.Get(key)
		t.Errorf("State leaked into database: %x -> %x", key, value)
	}
}

func TestCopy(t *testing.T) {
	orig, _ := New(common.Hash{}, common.Hash{}, common.Hash{}, NewDatabase(youdb.NewMemDatabase()))

	for i := byte(0); i < 255; i++ {
		obj := orig.GetOrNewStateObject(common.BytesToAddress([]byte{i}))
		obj.AddBalance(big.NewInt(int64(i)))
		orig.updateStateObject(obj)
	}

	copy := orig.Copy()

	for i := byte(0); i < 255; i++ {
		origObj := orig.GetOrNewStateObject(common.BytesToAddress([]byte{i}))
		copyObj := copy.GetOrNewStateObject(common.BytesToAddress([]byte{i}))

		origObj.AddBalance(big.NewInt(2 * int64(i)))
		copyObj.AddBalance(big.NewInt(3 * int64(i)))

		orig.updateStateObject(origObj)
		copy.updateStateObject(copyObj)
	}

	done := make(chan struct{})

	go func() {
		orig.Finalise(true)
		close(done)
	}()

	copy.Finalise(true)
	<-done

	for i := byte(0); i < 255; i++ {
		origObj := orig.GetOrNewStateObject(common.BytesToAddress([]byte{i}))
		copyObj := copy.GetOrNewStateObject(common.BytesToAddress([]byte{i}))

		if want := big.NewInt(3 * int64(i)); origObj.Balance().Cmp(want) != 0 {
			t.Errorf("orig obj %d: balance mismatch: have %v, want %v", i, origObj.Balance(), want)
		}

		if want := big.NewInt(4 * int64(i)); copyObj.Balance().Cmp(want) != 0 {
			t.Errorf("copy obj %d: balance mismatch: have %v, want %v", i, copyObj.Balance(), want)
		}
	}
}

func TestCopyOfCopy(t *testing.T) {
	sdb, _ := New(common.Hash{}, common.Hash{}, common.Hash{}, NewDatabase(youdb.NewMemDatabase()))
	addr := common.HexToAddress("aaaa")
	sdb.SetBalance(addr, big.NewInt(42))

	if got := sdb.Copy().GetBalance(addr).Uint64(); got != 42 {
		t.Fatalf("1st copy fail, expected 42, got %v", got)
	}
	if got := sdb.Copy().Copy().GetBalance(addr).Uint64(); got != 42 {
		t.Fatalf("2nd copy fail, expected 42, got %v", got)
	}
}
func TestAddressListRlpEncode(t *testing.T) {
	addrSet := []common.Address{}
	for i := 0; i < 1; i++ {
		addr := common.BigToAddress(big.NewInt(int64(i)))
		addrSet = append(addrSet, addr)
	}
	bs, err := rlp.EncodeToBytes(addrSet)
	fmt.Println(err)
	fmt.Println("len", len(bs), common.StorageSize(len(bs)).String())
}

func TestStateDB_CreateValidator(t *testing.T) {

	//region init
	db := youdb.NewMemDatabase()
	num := 10
	addrs := make([]common.Address, num)
	privateKeys := make([]*ecdsa.PrivateKey, num)
	pubKeys := make([][]byte, num)
	pubAddress := make([]common.Address, num)
	for i := 0; i < num; i++ {
		addrs[i] = common.BigToAddress(big.NewInt(int64(i)))

		key, _ := crypto.GenerateKey()
		privateKeys[i] = key
		pubKeys[i] = crypto.CompressPubkey(&key.PublicKey)
		pubAddress[i] = crypto.PubkeyToAddress(key.PublicKey)
	}
	//endregion

	var (
		stateSrc                                                                 *StateDB
		hashSrc, valRootSrc, hashCopy, valCopy, hashAdd, valAdd, hashDel, valDel common.Hash
	)
	stateSrc, _ = New(common.Hash{}, common.Hash{}, common.Hash{}, NewDatabase(db))

	{
		t.Log("init srouce statedb with 3 account and 3 validators")

		for i := 0; i < 3; i++ {
			stateSrc.CreateValidator(addrs[i].String(), addrs[i], addrs[i], params.RoleChancellor, pubKeys[i], pubKeys[i], big.NewInt(100000), big.NewInt(100000), params.AcceptDelegation, 2000, 1000, params.ValidatorOnline)
			stateSrc.AddBalance(addrs[i], big.NewInt(100))
		}
		hash, valRoot, _, err := stateSrc.Commit(true)
		assert.Nil(t, err)

		//持久化
		err = stateSrc.db.TrieDB().Commit(hash, false)
		assert.Nil(t, err)
		err = stateSrc.db.TrieDB().Commit(valRoot, false)
		assert.Nil(t, err)
		assert.Equal(t, 3, len(stateSrc.validatorIndex.List()))
		hashSrc = hash
		valRootSrc = valRoot

		t.Log("---------- init validators -------------------------------------------------------------")
		for _, v := range stateSrc.GetValidators().List() {
			t.Log("validator", "addr", v.MainAddress().String(), "stake", v.Stake, "status", v.Status, "role", v.Role)
		}
		t.Log("------------------------------------------------------------------------------------------")

	}

	t.Log("init hashSrc   ", hashSrc.String())
	t.Log("init valRootSrc", valRootSrc.String())

	{
		t.Log("copy srouce statedb, addrs[0].balance+=100")

		st := stateSrc.Copy()

		st.AddBalance(addrs[0], big.NewInt(100))

		hash, valRoot, _, _ := st.Commit(true)
		err := stateSrc.db.TrieDB().Commit(hash, false)
		assert.Nil(t, err)
		err = stateSrc.db.TrieDB().Commit(valRoot, false)
		assert.Nil(t, err)

		assert.Equal(t, 3, len(stateSrc.validatorIndex.List()))

		hashCopy = hash
		valCopy = valRoot
		assert.NotEqual(t, hashCopy.String(), hashSrc.String())
	}

	{
		t.Log("------------------------------------------------------------------------------------------")
		t.Log("copy source statedb, create validator")
		t.Log("------------------------------------------------------------------------------------------")
		stateCopy := stateSrc.Copy()

		t.Log("new validator", "val", addrs[3].String(), "addr", pubAddress[3].String())
		stateCopy.CreateValidator(addrs[3].String(), addrs[3], addrs[3], params.RoleChancellor, pubKeys[3], pubKeys[3], big.NewInt(400000), big.NewInt(400000), params.AcceptDelegation, 2000, 1000, params.ValidatorOnline)
		stateCopy.AddBalance(addrs[0], big.NewInt(200))

		hash, valRoot, _, _ := stateCopy.Commit(true)
		err := stateCopy.db.TrieDB().Commit(hash, false)
		assert.Nil(t, err)
		err = stateSrc.db.TrieDB().Commit(valRoot, false)
		assert.Nil(t, err)
		hashAdd = hash
		valAdd = valRoot
		assert.NotEqual(t, hashAdd.String(), hashSrc.String())

		t.Log("after create validator", "count", stateCopy.GetValidators().Len())
		for _, v := range stateCopy.GetValidators().List() {
			t.Log("validator", "addr", v.MainAddress().String(), "stake", v.Stake, "status", v.Status, "role", v.Role)
		}
		t.Log("------------------------------------------------------------------------------------------")
	}

	{
		t.Log("------------------------------------------------------------------------------------------")
		t.Log("copy source statedb, delete validator", pubAddress[0].String())
		t.Log("------------------------------------------------------------------------------------------")

		stateCopy := stateSrc.Copy()
		stateCopy.loadAllValidators()
		vals := stateCopy.GetValidators()
		valsCount := vals.Len()
		t.Log("validators count before delete", "count", valsCount)
		for _, val := range vals.List() {
			t.Log("val", "addr", val.MainAddress().String())
		}
		assert.True(t, stateCopy.RemoveValidator(pubAddress[0]))

		hash, valRoot, _, _ := stateCopy.Commit(true)
		err := stateCopy.db.TrieDB().Commit(hash, false)
		assert.Nil(t, err)
		err = stateSrc.db.TrieDB().Commit(valRoot, false)
		assert.Nil(t, err)
		t.Log("validators count after delete", "count", stateCopy.GetValidators().Len())

		hashDel = hash
		valDel = valRoot
		assert.Equal(t, hashDel.String(), hashSrc.String())
		assert.NotEqual(t, valDel.String(), valRootSrc.String())
		t.Log("------------------------------------------------------------------------------------------")
	}

	{
		t.Log("------------------------------------------------------------------------------------------")
		t.Log("open hashSrc", hashSrc.String())
		t.Log("------------------------------------------------------------------------------------------")

		st, _ := New(hashSrc, valRootSrc, common.Hash{}, NewDatabase(db))
		t.Log("open hashSrc validators", len(st.validatorIndex.List()))
		assert.Equal(t, 3, len(st.validatorIndex.List()))
		// fmt.Println("open hashSrc addr", addrs[0].String(), "=", st.GetBalance(addrs[0]))
		// fmt.Println("open hashSrc addr", addrs[1].String(), "=", st.GetBalance(addrs[1]))
		// fmt.Println("open hashSrc addr", addrs[2].String(), "=", st.GetBalance(addrs[2]))
		// fmt.Println("open hashSrc addr", addrs[3].String(), "=", st.GetBalance(addrs[3]))

		t.Log("------------------------------------------------------------------------------------------")
	}
	{
		t.Log("------------------------------------------------------------------------------------------")
		t.Log("open hashCopy", hashCopy.String())
		t.Log("------------------------------------------------------------------------------------------")

		st, _ := New(hashCopy, valCopy, common.Hash{}, NewDatabase(db))
		assert.Equal(t, 3, len(st.validatorIndex.List()))
		assert.Equal(t, uint64(200), st.GetBalance(addrs[0]).Uint64())
		// fmt.Println("open hashCopy addr", addrs[0].String(), "=", st.GetBalance(addrs[0]).Uint64())
		// fmt.Println("open hashCopy addr", addrs[1].String(), "=", st.GetBalance(addrs[1]).Uint64())
		// fmt.Println("open hashCopy addr", addrs[2].String(), "=", st.GetBalance(addrs[2]).Uint64())
		// fmt.Println("open hashCopy addr", addrs[3].String(), "=", st.GetBalance(addrs[3]).Uint64())
	}
	{
		t.Log("------------------------------------------------------------------------------------------")
		t.Log("open hashAdd", hashAdd.String())
		t.Log("------------------------------------------------------------------------------------------")

		st, _ := New(hashAdd, valAdd, common.Hash{}, NewDatabase(db))
		assert.Equal(t, 4, len(st.validatorIndex.List()))
		assert.Equal(t, uint64(300), st.GetBalance(addrs[0]).Uint64())
		// fmt.Println("open hashAdd addr", addrs[0].String(), "=", st.GetBalance(addrs[0]))
		// fmt.Println("open hashAdd addr", addrs[1].String(), "=", st.GetBalance(addrs[1]))
		// fmt.Println("open hashAdd addr", addrs[2].String(), "=", st.GetBalance(addrs[2]))
		// fmt.Println("open hashAdd addr", addrs[3].String(), "=", st.GetBalance(addrs[3]))
		t.Log("------------------------------------------------------------------------------------------")
	}
	{
		t.Log("------------------------------------------------------------------------------------------")
		t.Log("open hashDel", hashDel.String())
		t.Log("------------------------------------------------------------------------------------------")

		st, _ := New(hashDel, valDel, common.Hash{}, NewDatabase(db))
		t.Log("open hashDel valiators", len(st.validatorIndex.List()))
		assert.Equal(t, 2, len(st.validatorIndex.List()))
		assert.Equal(t, uint64(100), st.GetBalance(addrs[0]).Uint64())
		// fmt.Println("open hashDel addr", addrs[0].String(), "=", st.GetBalance(addrs[0]))
		// fmt.Println("open hashDel addr", addrs[1].String(), "=", st.GetBalance(addrs[1]))
		// fmt.Println("open hashDel addr", addrs[2].String(), "=", st.GetBalance(addrs[2]))
		// fmt.Println("open hashDel addr", addrs[3].String(), "=", st.GetBalance(addrs[3]))
		t.Log("------------------------------------------------------------------------------------------")
	}

	{
		t.Log("------------------------------------------------------------------------------------------")
		t.Log("reopen statedb hashSrc", hashSrc.String())
		t.Log("------------------------------------------------------------------------------------------")

		st, err := New(hashSrc, valRootSrc, common.Hash{}, NewDatabase(db))
		st.loadAllValidators()
		assert.NoError(t, err)
		assert.Equal(t, 3, len(st.validatorIndex.List()))
		assert.Equal(t, uint64(100), st.GetBalance(addrs[0]).Uint64())
		t.Log("reopen statedb hashSrc valiators", len(st.validatorIndex.List()))
		// fmt.Println("reopen statedb hashSrc addr", addrs[0].String(), "=", st.GetBalance(addrs[0]))
		// fmt.Println("reopen statedb hashSrc addr", addrs[1].String(), "=", st.GetBalance(addrs[1]))
		// fmt.Println("reopen statedb hashSrc addr", addrs[2].String(), "=", st.GetBalance(addrs[2]))
		// fmt.Println("reopen statedb hashSrc addr", addrs[3].String(), "=", st.GetBalance(addrs[3]))
		t.Log("------------------------------------------------------------------------------------------")
	}

	t.Log("END")
}

func TestStateDB_CreateValidator2(t *testing.T) {
	db := youdb.NewMemDatabase()
	state, _ := New(common.Hash{}, common.Hash{}, common.Hash{}, NewDatabase(db))
	privateKey, _ := crypto.GenerateKey()
	publicKey := crypto.CompressPubkey(&privateKey.PublicKey)
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	newVal := state.CreateValidator(address.String(), address, address, params.RoleChancellor, hexutil.Bytes(publicKey), hexutil.Bytes(publicKey), big.NewInt(1), big.NewInt(1), params.AcceptDelegation, 2000, 1000, params.ValidatorOnline)
	assert.NotNil(t, newVal)
}

func TestStateDB_DeleteEmptyValidator(t *testing.T) {
	//region init
	db := youdb.NewMemDatabase()
	num := 3
	addrs := make([]common.Address, num)
	privateKeys := make([]*ecdsa.PrivateKey, num)
	pubKeys := make([][]byte, num)
	pubAddress := make([]common.Address, num)
	for i := 0; i < num; i++ {
		addrs[i] = common.BigToAddress(big.NewInt(int64(i)))

		key, _ := crypto.GenerateKey()
		privateKeys[i] = key
		pubKeys[i] = crypto.CompressPubkey(&key.PublicKey)
		pubAddress[i] = crypto.PubkeyToAddress(key.PublicKey)
	}
	//endregion

	vals := make([]*Validator, num)
	st, _ := New(common.Hash{}, common.Hash{}, common.Hash{}, NewDatabase(db))
	for i := 0; i < num; i++ {
		v := st.CreateValidator(addrs[i].String(), addrs[i], addrs[i], params.RoleChancellor, pubKeys[i], pubKeys[i], big.NewInt(100000), big.NewInt(100000), params.AcceptDelegation, 2000, 1000, params.ValidatorOnline)
		//st.AddBalance(addrs[i], big.NewInt(100))
		vals[i] = v
	}

	//
	v := vals[0]
	nv := v.PartialCopy()
	nv.Stake.SetInt64(0)
	nv.Token.SetInt64(0)
	st.UpdateValidator(nv, v)

	root, valRoot, _ := st.IntermediateRoot(true)
	// deleteEmptyObjects?
	stat, err := st.GetValidatorsStat()
	require.NoError(t, err)
	require.EqualValues(t, uint64(num-1), stat.GetByRole(v.Role).onlineCount)

	root2, valRoot2, _, err := st.Commit(true)
	require.NoError(t, err)
	require.EqualValues(t, root, root2)
	require.EqualValues(t, valRoot, valRoot2)

}

func TestStateDB_GetValidatorsForUpdate(t *testing.T) {
	db := youdb.NewMemDatabase()
	num := 3
	addrs := make([]common.Address, num)
	privateKeys := make([]*ecdsa.PrivateKey, num)
	pubKeys := make([][]byte, num)
	pubAddress := make([]common.Address, num)
	for i := 0; i < num; i++ {
		addrs[i] = common.BigToAddress(big.NewInt(int64(i)))

		key, _ := crypto.GenerateKey()
		privateKeys[i] = key
		pubKeys[i] = crypto.CompressPubkey(&key.PublicKey)
		pubAddress[i] = crypto.PubkeyToAddress(key.PublicKey)
	}
	st, _ := New(common.Hash{}, common.Hash{}, common.Hash{}, NewDatabase(db))
	for i := 0; i < num; i++ {
		_ = st.CreateValidator(addrs[i].String(), addrs[i], addrs[i], params.RoleChancellor, pubKeys[i], pubKeys[i], big.NewInt(100000), big.NewInt(100000), params.AcceptDelegation, 2000, 1000, params.ValidatorOnline)
	}

	st.Finalise(true)

	//test update iteratively
	vals := st.GetValidatorsForUpdate()
	for i, v := range vals {
		if i&1 == 0 {
			old := v.PartialCopy()
			v.UpdateLastActive(100)
			st.UpdateValidator(v, old)
		} else {
			newVal := v.PartialCopy()
			newVal.UpdateLastActive(100)
			st.UpdateValidator(newVal, v)
		}
	}

	// does the updates takes effects?
	for _, v := range st.GetValidatorsForUpdate() {
		assert.Equal(t, uint64(100), v.LastActive())
	}
}
