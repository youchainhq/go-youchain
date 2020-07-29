// Copyright 2015 The go-ethereum Authors
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
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/youchainhq/go-youchain/bls"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/trie"
	"github.com/youchainhq/go-youchain/youdb"
)

// testAccount is the data associated with an account used by the state tests.
type testAccount struct {
	address common.Address
	balance *big.Int
	nonce   uint64
	code    []byte

	delegationHash []byte
}

// makeTestState create a sample test state to test node-wise reconstruction.
func makeTestState() (Database, common.Hash, common.Hash, common.Hash, []*testAccount) {
	// Create an empty state
	db := NewDatabase(youdb.NewMemDatabase())
	state, _ := New(common.Hash{}, common.Hash{}, common.Hash{}, db)

	// Fill it with some arbitrary data
	accounts := []*testAccount{}
	delegators := make([]*stateObject, 0, 32)
	for i := byte(0); i < 96; i++ {
		obj := state.GetOrNewStateObject(common.BytesToAddress([]byte{i}))
		acc := &testAccount{address: common.BytesToAddress([]byte{i})}

		obj.AddBalance(big.NewInt(int64(11 * i)))
		acc.balance = big.NewInt(int64(11 * i))

		obj.SetNonce(uint64(42 * i))
		acc.nonce = uint64(42 * i)

		if i%3 == 0 {
			obj.SetCode(crypto.Keccak256Hash([]byte{i, i, i, i, i}), []byte{i, i, i, i, i})
			acc.code = []byte{i, i, i, i, i}
			delegators = append(delegators, obj)
		}
		state.updateStateObject(obj)
		accounts = append(accounts, acc)
	}

	blsMgr := bls.NewBlsManager()
	validators := make([]*Validator, 0, 256)
	for i := 0; i < 256; i++ {
		key, _ := crypto.GenerateKey()
		blsK, _ := blsMgr.GenerateKey()
		addr := crypto.PubkeyToAddress(key.PublicKey)
		mainPubKey := crypto.CompressPubkey(&key.PublicKey)
		blsP, _ := blsK.PubKey()
		blsPubKey := blsP.Compress().Bytes()
		val := state.CreateValidator(addr.String(), addr, addr, params.RoleChancellor, mainPubKey, blsPubKey, big.NewInt(10), big.NewInt(10), params.AcceptDelegation, 2000, 1000, params.ValidatorOnline)
		validators = append(validators, val)
	}

	// TODO: why NewValidatorsStat?
	//stat := NewValidatorsStat()
	//bs, _ := rlp.EncodeToBytes(&stat)
	//state.updateStakingData(common.Address{}, validatorStatFlag, bs)

	for i, d := range delegators {
		// add delegation
		v := validators[i%3]
		value := new(big.Int).Mul(big.NewInt(100+int64(i)), params.StakeUint)
		state.UpdateDelegation(d.address, v, value)

		//add stakingRecord
		state.AddStakingRecord(d.address, v.MainAddress(), common.BytesToHash([]byte{0xff, byte(i)}), value)
		// records the DelegationHash
		accounts[i*3].delegationHash = d.DelegationsHash()
	}
	root, valRoot, stakingRoot, _ := state.Commit(true)

	// Return the generated state
	return db, root, valRoot, stakingRoot, accounts
}

// checkStateAccounts cross references a reconstructed state with an expected
// account array.
func checkStateAccounts(t *testing.T, dstDb youdb.Database, root, valRoot, stakingRoot common.Hash, accounts []*testAccount) {
	// Check root availability and state contents
	logging.Info("check state accounts", "root", root.String(), "valRoot", valRoot.String(), "stakingRoot", stakingRoot.String())
	state, err := New(root, valRoot, stakingRoot, NewDatabase(dstDb))
	if err != nil {
		t.Fatalf("failed to create state trie at %x: %v", root, err)
	}
	if err := checkStateConsistency(dstDb, root, valRoot, stakingRoot); err != nil {
		t.Fatalf("inconsistent state trie at %x: %v", root, err)
	}
	for i, acc := range accounts {
		if balance := state.GetBalance(acc.address); balance.Cmp(acc.balance) != 0 {
			t.Errorf("account %d: balance mismatch: have %v, want %v", i, balance, acc.balance)
		}
		if nonce := state.GetNonce(acc.address); nonce != acc.nonce {
			t.Errorf("account %d: nonce mismatch: have %v, want %v", i, nonce, acc.nonce)
		}
		if code := state.GetCode(acc.address); !bytes.Equal(code, acc.code) {
			t.Errorf("account %d: code mismatch: have %x, want %x", i, code, acc.code)
		}
	}

	stat, err := state.getValidatorsStat()
	bs, _ := json.Marshal(stat.Dump())
	fmt.Println(string(bs))
	assert.Nil(t, err)
	assert.NotNil(t, stat)
}

// checkTrieConsistency checks that all nodes in a (sub-)trie are indeed present.
func checkTrieConsistency(db youdb.Database, root common.Hash) error {
	// Create and iterate a state trie rooted in a sub-node
	if v, _ := db.Get(root.Bytes()); v == nil {
		return nil // Consider a non existent state consistent.
	}

	trie, err := trie.New(root, trie.NewDatabase(db))
	if err != nil {
		return err
	}
	it := trie.NodeIterator(nil)
	for it.Next(true) {
	}
	return it.Error()
}

// checkStateConsistency checks that all data of a state root is present.
func checkStateConsistency(db youdb.Database, root, valRoot, stakingRoot common.Hash) error {
	roots := []common.Hash{root, valRoot, stakingRoot}
	// Create and iterate a state trie rooted in a sub-node
	for _, r := range roots {
		if _, err := db.Get(r.Bytes()); err != nil {
			return nil // Consider a non existent state consistent.
		}
	}

	state, err := New(root, valRoot, stakingRoot, NewDatabase(db))
	if err != nil {
		return err
	}
	// check stateTrie iterator
	it := NewNodeIterator(state)
	for it.Next() {
	}
	if it.Error != nil {
		return it.Error
	}
	//check other tries
	tries := []Trie{state.valTrie, state.stakingTrie}
	for _, tr := range tries {
		it := trie.NewIterator(tr.NodeIterator(nil))
		for it.Next() {
		}
		if it.Err != nil {
			return it.Err
		}
	}
	return nil
}

func TestNewStateSync(t *testing.T) {
	mem := youdb.NewMemDatabase()
	db := NewDatabase(mem)
	sss, _ := trie.New(common.Hash{}, db.TrieDB())
	fmt.Println(sss.Hash().String())

	//addr := common.HexToAddress("1")
	//mem := youdb.NewMemDatabase()
	//tmp := common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
	//st, _ := New(tmp, db)
	//st.SetBalance(addr, big.NewInt(1000))
	//st.Commit(false)
	//
	//sync := NewStateSync(tmp, mem)
	//fmt.Println(sync.Pending())
}

// Tests that an empty state is not scheduled for syncing.
func TestEmptyStateSync(t *testing.T) {
	empty := common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
	if req := NewStateSync(empty, youdb.NewMemDatabase()).Missing(1); len(req) != 0 {
		t.Errorf("content requested for empty state: %v", req)
	}
}

// Tests that given a root hash, a state can sync iteratively on a single thread,
// requesting retrieval tasks and returning all of them in one go.
func TestIterativeStateSyncIndividual(t *testing.T) { testIterativeStateSync(t, 1) }
func TestIterativeStateSyncBatched(t *testing.T)    { testIterativeStateSync(t, 100) }

func testIterativeStateSync(t *testing.T, count int) {
	// Create a random state to copy
	srcDb, srcRoot, srcValRoot, srcStakingRoot, srcAccounts := makeTestState()
	roots := []common.Hash{srcRoot, srcValRoot, srcStakingRoot}

	logging.Info("make state", "srcRoot", srcRoot.String(), "srcValRoot", srcValRoot.String(), "srcStakingRoot", srcStakingRoot.String())
	for _, r := range roots {
		if err := srcDb.TrieDB().Commit(r, false); err != nil {
			assert.NoError(t, err)
		}
	}

	// Create a destination state and sync with the scheduler
	dstDb := youdb.NewMemDatabase()
	for i, r := range roots {
		var sched *trie.Sync
		if i == 0 {
			sched = NewStateSync(r, dstDb)
		} else {
			sched = NewSync(r, dstDb)
		}
		queue := append([]common.Hash{}, sched.Missing(count)...)
		for len(queue) > 0 {
			results := make([]trie.SyncResult, len(queue))
			for i, hash := range queue {
				data, err := srcDb.TrieDB().Node(hash)
				if err != nil {
					t.Fatalf("failed to retrieve node data for %x", hash)
				}
				results[i] = trie.SyncResult{Hash: hash, Data: data}
			}
			if _, index, err := sched.Process(results); err != nil {
				t.Fatalf("failed to process result #%d: %v", index, err)
			}
			batch := dstDb.NewBatch()
			if _, err := sched.Commit(batch); err != nil {
				t.Fatalf("failed to commit data: %v", err)
			}
			batch.Write()
			queue = append(queue[:0], sched.Missing(count)...)
		}
	}

	// Cross check that the two states are in sync
	checkStateAccounts(t, dstDb, srcRoot, srcValRoot, srcStakingRoot, srcAccounts)
}

// Tests that the trie scheduler can correctly reconstruct the state even if only
// partial results are returned, and the others sent only later.
func TestIterativeDelayedStateSync(t *testing.T) {
	// Create a random state to copy
	srcDb, srcRoot, srcValRoot, srcStakingRoot, srcAccounts := makeTestState()
	roots := []common.Hash{srcRoot, srcValRoot, srcStakingRoot}

	// Create a destination state and sync with the scheduler
	dstDb := youdb.NewMemDatabase()

	for i, r := range roots {
		var sched *trie.Sync
		if i == 0 {
			sched = NewStateSync(r, dstDb)
		} else {
			sched = NewSync(r, dstDb)
		}
		queue := append([]common.Hash{}, sched.Missing(0)...)
		for len(queue) > 0 {
			// Sync only half of the scheduled nodes
			results := make([]trie.SyncResult, len(queue)/2+1)
			for i, hash := range queue[:len(results)] {
				data, err := srcDb.TrieDB().Node(hash)
				if err != nil {
					t.Fatalf("failed to retrieve node data for %x", hash)
				}
				results[i] = trie.SyncResult{Hash: hash, Data: data}
			}
			if _, index, err := sched.Process(results); err != nil {
				t.Fatalf("failed to process result #%d: %v", index, err)
			}
			batch := dstDb.NewBatch()
			if _, err := sched.Commit(batch); err != nil {
				t.Fatalf("failed to commit data: %v", err)
			}
			batch.Write()
			queue = append(queue[len(results):], sched.Missing(0)...)
		}
	}

	// Cross check that the two states are in sync
	checkStateAccounts(t, dstDb, srcRoot, srcValRoot, srcStakingRoot, srcAccounts)
}

// Tests that given a root hash, a trie can sync iteratively on a single thread,
// requesting retrieval tasks and returning all of them in one go, however in a
// random order.
func TestIterativeRandomStateSyncIndividual(t *testing.T) { testIterativeRandomStateSync(t, 1) }
func TestIterativeRandomStateSyncBatched(t *testing.T)    { testIterativeRandomStateSync(t, 100) }

func testIterativeRandomStateSync(t *testing.T, count int) {
	// Create a random state to copy
	srcDb, srcRoot, srcValRoot, srcStakingRoot, srcAccounts := makeTestState()
	roots := []common.Hash{srcRoot, srcValRoot, srcStakingRoot}

	// Create a destination state and sync with the scheduler
	dstDb := youdb.NewMemDatabase()

	for i, r := range roots {
		var sched *trie.Sync
		if i == 0 {
			sched = NewStateSync(r, dstDb)
		} else {
			sched = NewSync(r, dstDb)
		}
		queue := make(map[common.Hash]struct{})
		for _, hash := range sched.Missing(count) {
			queue[hash] = struct{}{}
		}
		for len(queue) > 0 {
			// Fetch all the queued nodes in a random order
			results := make([]trie.SyncResult, 0, len(queue))
			for hash := range queue {
				data, err := srcDb.TrieDB().Node(hash)
				if err != nil {
					t.Fatalf("failed to retrieve node data for %x", hash)
				}
				results = append(results, trie.SyncResult{Hash: hash, Data: data})
			}
			// Feed the retrieved results back and queue new tasks
			if _, index, err := sched.Process(results); err != nil {
				t.Fatalf("failed to process result #%d: %v", index, err)
			}
			batch := dstDb.NewBatch()
			if _, err := sched.Commit(batch); err != nil {
				t.Fatalf("failed to commit data: %v", err)
			}
			batch.Write()
			queue = make(map[common.Hash]struct{})
			for _, hash := range sched.Missing(count) {
				queue[hash] = struct{}{}
			}
		}
	}

	// Cross check that the two states are in sync
	checkStateAccounts(t, dstDb, srcRoot, srcValRoot, srcStakingRoot, srcAccounts)
}

// Tests that the trie scheduler can correctly reconstruct the state even if only
// partial results are returned (Even those randomly), others sent only later.
func TestIterativeRandomDelayedStateSync(t *testing.T) {
	// Create a random state to copy
	srcDb, srcRoot, srcValRoot, srcStakingRoot, srcAccounts := makeTestState()
	roots := []common.Hash{srcRoot, srcValRoot, srcStakingRoot}

	// Create a destination state and sync with the scheduler
	dstDb := youdb.NewMemDatabase()

	for i, r := range roots {
		var sched *trie.Sync
		if i == 0 {
			sched = NewStateSync(r, dstDb)
		} else {
			sched = NewSync(r, dstDb)
		}
		queue := make(map[common.Hash]struct{})
		for _, hash := range sched.Missing(0) {
			queue[hash] = struct{}{}
		}
		for len(queue) > 0 {
			// Sync only half of the scheduled nodes, even those in random order
			results := make([]trie.SyncResult, 0, len(queue)/2+1)
			for hash := range queue {
				delete(queue, hash)

				data, err := srcDb.TrieDB().Node(hash)
				if err != nil {
					t.Fatalf("failed to retrieve node data for %x", hash)
				}
				results = append(results, trie.SyncResult{Hash: hash, Data: data})

				if len(results) >= cap(results) {
					break
				}
			}
			// Feed the retrieved results back and queue new tasks
			if _, index, err := sched.Process(results); err != nil {
				t.Fatalf("failed to process result #%d: %v", index, err)
			}
			batch := dstDb.NewBatch()
			if _, err := sched.Commit(batch); err != nil {
				t.Fatalf("failed to commit data: %v", err)
			}
			batch.Write()
			for _, hash := range sched.Missing(0) {
				queue[hash] = struct{}{}
			}
		}
	}

	// Cross check that the two states are in sync
	checkStateAccounts(t, dstDb, srcRoot, srcValRoot, srcStakingRoot, srcAccounts)
}

// Tests that at any point in time during a sync, only complete sub-tries are in
// the database.
func TestIncompleteStateSync(t *testing.T) {
	// Create a random state to copy
	srcDb, srcRoot, srcValRoot, srcStakingRoot, srcAccounts := makeTestState()
	err := checkStateConsistency(srcDb.TrieDB().DiskDB(), srcRoot, srcValRoot, srcStakingRoot)
	require.NoError(t, err)
	err = checkTrieConsistency(srcDb.TrieDB().DiskDB(), srcRoot)
	require.NoError(t, err)

	// Create a destination state and sync with the scheduler
	dstDb := youdb.NewMemDatabase()
	roots := []common.Hash{srcRoot, srcValRoot, srcStakingRoot}
	added := make([][]common.Hash, 3)

	for i, r := range roots {
		var sched *trie.Sync
		if i == 0 {
			sched = NewStateSync(r, dstDb)
		} else {
			sched = NewSync(r, dstDb)
		}
		added[i] = make([]common.Hash, 0)

		queue := append([]common.Hash{}, sched.Missing(1)...)
		for len(queue) > 0 {
			// Fetch a batch of state nodes
			results := make([]trie.SyncResult, len(queue))
			for i, hash := range queue {
				data, err := srcDb.TrieDB().Node(hash)
				if err != nil {
					t.Fatalf("failed to retrieve node data for %x", hash)
				}
				results[i] = trie.SyncResult{Hash: hash, Data: data}
			}
			// Process each of the state nodes
			if _, index, err := sched.Process(results); err != nil {
				t.Fatalf("failed to process result #%d: %v", index, err)
			}
			batch := dstDb.NewBatch()
			if index, err := sched.Commit(batch); err != nil {
				t.Fatalf("failed to commit data #%d: %v", index, err)
			}
			batch.Write()
			for _, result := range results {
				added[i] = append(added[i], result.Hash)
			}

			if i == 0 {
				// Check that all known sub-tries added so far are complete or missing entirely.
			checkSubtries:
				for _, hash := range added[0] {
					for _, acc := range srcAccounts {
						if hash == crypto.Keccak256Hash(acc.code) {
							continue checkSubtries // skip trie check of code nodes.
						}
						if hash == common.BytesToHash(acc.delegationHash) {
							continue checkSubtries
						}
					}
					// Can't use checkStateConsistency here because subtrie keys may have odd
					// length and crash in LeafKey.
					if err := checkTrieConsistency(dstDb, hash); err != nil {
						t.Fatalf("state inconsistent: %v", err)
					}
				}
			}
			// Fetch the next batch to retrieve
			queue = append(queue[:0], sched.Missing(1)...)
		}
	}
	// Sanity check that removing any node from the database is detected
	for i, nodes := range added {
		for _, node := range nodes[1:] {
			key := node.Bytes()
			value, _ := dstDb.Get(key)
			dstDb.Delete(key)
			if err := checkStateConsistency(dstDb, srcRoot, srcValRoot, srcStakingRoot); err == nil {
				t.Fatalf("trie %d inconsistency not caught, missing: %x", i, key)
			}
			dstDb.Put(key, value)
		}
	}

	// Sanity check valTrie
	db := NewDatabase(dstDb)
	for _, node := range added[1][1:] {
		key := node.Bytes()
		value, _ := dstDb.Get(key)

		dstDb.Delete(key)
		if _, err := NewVldReader(srcValRoot, db, true); err == nil {
			t.Fatalf("trie inconsistency not caught, missing: %x", key)
		}
		dstDb.Put(key, value)
	}
}
