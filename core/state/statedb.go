// Copyright 2014 The go-ethereum Authors
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

// Package state provides a caching layer atop the Ethereum state trie.
package state

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/trie"
)

type revision struct {
	id           int
	journalIndex int
}

var (
	// emptyState is the known hash of an empty state trie entry.
	emptyState = crypto.Keccak256Hash(nil)

	emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

	// emptyCode is the known hash of the empty EVM bytecode.
	emptyCode = crypto.Keccak256Hash(nil)
)

type proofList [][]byte

func (n *proofList) Put(key []byte, value []byte) error {
	*n = append(*n, value)
	return nil
}

// StateDBs within the ethereum protocol are used to store anything
// within the merkle trie. StateDBs take care of caching and storing
// nested states. It's the general query interface to retrieve:
// * Contracts
// * Accounts
// the valTrie is used to store validators and global stat.
// the global stat data will be stored with a special key.
type StateDB struct {
	db   Database
	trie Trie
	// This map holds 'live' objects, which will get modified while processing a state transition.
	stateObjects        map[common.Address]*stateObject
	stateObjectsPending map[common.Address]struct{} // State objects finalized but not yet written to the trie
	stateObjectsDirty   map[common.Address]struct{}

	valTrie Trie
	// This map holds 'live' objects, which will get modified while processing a state transition.
	validatorObjects       sync.Map
	validatorObjectsDirty  map[common.Address]struct{} // consAddress => validator
	validatorIndex         *ValidatorIndex             // all validator's address
	validatorsStat         atomic.Value                // cache for total stake
	validatorsStatModified bool

	validatorsSorted atomic.Value // cache of all validators
	withdrawQueue    atomic.Value

	// the pending staking trie
	stakingTrie Trie
	// this map holds 'live' pending records, which will get modified while processing a staking transaction
	stakingRecords      map[biAddress]*stakingRecord
	stakingRecordsDirty map[biAddress]struct{}
	// this holds the pending unique delegation relationship from delegator to validator
	pendingRelats      *pendingRelationship
	pendingRelatsDirty bool

	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be returned
	// by StateDB.Commit.
	dbErr error

	// The refund counter, also used by state transitioning.
	refund uint64

	thash, bhash common.Hash
	txIndex      int
	logs         map[common.Hash][]*types.Log
	logSize      uint

	preimages map[common.Hash][]byte

	// Journal of state modifications. This is the backbone of
	// Snapshot and RevertToSnapshot.
	journal           *journal
	validatorJournal  *journal
	validRevisions    []revision
	valValidRevisions []revision
	nextRevisionId    int
}

func (st *StateDB) ValidatorsModified() bool {
	return st.validatorsStatModified
}

// Create a new state from the given tries.
func New(root, valRoot, stakingRoot common.Hash, db Database) (*StateDB, error) {
	var tries [3]Trie
	roots := []struct {
		name string
		root common.Hash
	}{{"stateRoot", root}, {"valRoot", valRoot}, {"stakingRoot", stakingRoot}}
	for i, rt := range roots {
		t, err := db.OpenTrie(rt.root)
		if err != nil {
			return nil, fmt.Errorf("open trie error, name=%s, root=%s, err=%v", rt.name, rt.root.String(), err)
		}
		tries[i] = t
	}
	st := &StateDB{
		db:                  db,
		trie:                tries[0],
		stateObjects:        make(map[common.Address]*stateObject),
		stateObjectsPending: make(map[common.Address]struct{}),
		stateObjectsDirty:   make(map[common.Address]struct{}),

		valTrie:               tries[1],
		validatorObjects:      sync.Map{},
		validatorIndex:        NewValidatorIndex(),
		validatorObjectsDirty: make(map[common.Address]struct{}),

		stakingTrie:         tries[2],
		stakingRecords:      make(map[biAddress]*stakingRecord),
		stakingRecordsDirty: make(map[biAddress]struct{}),

		logs:             make(map[common.Hash][]*types.Log),
		preimages:        make(map[common.Hash][]byte),
		journal:          newJournal(),
		validatorJournal: newJournal(),
	}

	//load address list
	if err := st.getValidatorsIndex(); err != nil {
		logging.Error("load validator index failed", "err", err, "root", root.String())
		return nil, fmt.Errorf("load validator index failed, err=%v", err)
	}
	if _, err := st.getValidatorsStat(); err != nil {
		return nil, fmt.Errorf("load validator stats failed, err=%v", err)
	}

	if err := st.loadPendingRelationship(); err != nil {
		return nil, fmt.Errorf("load pending relationship failed, err=%v", err)
	}

	return st, nil
}

// setError remembers the first non-nil error it is called with.
func (st *StateDB) setError(err error) {
	if st.dbErr == nil {
		st.dbErr = err
	}
}

func (st *StateDB) Error() error {
	return st.dbErr
}

// ResetStakingTrie will force the staking trie to start a new trie
func (st *StateDB) ResetStakingTrie() {
	st.stakingTrie, _ = st.db.OpenTrie(common.Hash{})
	st.stakingRecords = make(map[biAddress]*stakingRecord)
	st.stakingRecordsDirty = make(map[biAddress]struct{})
	st.pendingRelats = newPendingRelationship()
	st.pendingRelatsDirty = false
}

// Reset clears out all ephemeral state objects from the state db, but keeps
// the underlying state trie to avoid reloading data for the next operations.
func (st *StateDB) Reset(root, valRoot common.Hash) error {
	tr, err := st.db.OpenTrie(root)
	if err != nil {
		return err
	}
	st.trie = tr
	st.stateObjects = make(map[common.Address]*stateObject)
	st.stateObjectsPending = make(map[common.Address]struct{})
	st.stateObjectsDirty = make(map[common.Address]struct{})

	vtr, err := st.db.OpenTrie(valRoot)
	if err != nil {
		return err
	}
	st.valTrie = vtr

	st.validatorObjects = sync.Map{}
	st.validatorObjectsDirty = make(map[common.Address]struct{})
	st.validatorIndex = NewValidatorIndex()

	st.thash = common.Hash{}
	st.bhash = common.Hash{}
	st.txIndex = 0
	st.logs = make(map[common.Hash][]*types.Log)
	st.logSize = 0
	st.preimages = make(map[common.Hash][]byte)
	st.clearJournalAndRefund()
	return nil
}

func (st *StateDB) AddLog(log *types.Log) {
	st.journal.append(addLogChange{txhash: st.thash})

	log.TxHash = st.thash
	log.BlockHash = st.bhash
	log.TxIndex = uint(st.txIndex)
	log.Index = st.logSize
	st.logs[st.thash] = append(st.logs[st.thash], log)
	st.logSize++
}

func (st *StateDB) GetLogs(hash common.Hash) []*types.Log {
	return st.logs[hash]
}

func (st *StateDB) Logs() []*types.Log {
	var logs []*types.Log
	for _, lgs := range st.logs {
		logs = append(logs, lgs...)
	}
	return logs
}

// AddPreimage records a SHA3 preimage seen by the VM.
func (st *StateDB) AddPreimage(hash common.Hash, preimage []byte) {
	if _, ok := st.preimages[hash]; !ok {
		st.journal.append(addPreimageChange{hash: hash})
		pi := make([]byte, len(preimage))
		copy(pi, preimage)
		st.preimages[hash] = pi
	}
}

// Preimages returns a list of SHA3 preimages that have been submitted.
func (st *StateDB) Preimages() map[common.Hash][]byte {
	return st.preimages
}

func (st *StateDB) AddRefund(gas uint64) {
	st.journal.append(refundChange{prev: st.refund})
	st.refund += gas
}

// SubRefund removes gas from the refund counter.
// This method will panic if the refund counter goes below zero
func (st *StateDB) SubRefund(gas uint64) {
	st.journal.append(refundChange{prev: st.refund})
	if gas > st.refund {
		panic(fmt.Sprintf("Refund counter below zero (gas: %d > refund: %d)", gas, st.refund))
	}
	st.refund -= gas
}

// Exist reports whether the given account address exists in the state.
// Notably this also returns true for suicided accounts.
func (st *StateDB) Exist(addr common.Address) bool {
	return st.getStateObject(addr) != nil
}

// Empty returns whether the state object is either non-existent
// or empty according to the EIP161 specification (balance = nonce = code = 0)
func (st *StateDB) Empty(addr common.Address) bool {
	so := st.getStateObject(addr)
	return so == nil || so.empty()
}

// Retrieve the balance from the given address or 0 if object not found
func (st *StateDB) GetBalance(addr common.Address) *big.Int {
	stateObject := st.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Balance()
	}
	return common.Big0()
}

func (st *StateDB) GetNonce(addr common.Address) uint64 {
	stateObject := st.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Nonce()
	}

	return 0
}

// TxIndex returns the current transaction index set by Prepare.
func (st *StateDB) TxIndex() int {
	return st.txIndex
}

// BlockHash returns the current block hash set by Prepare.
func (st *StateDB) BlockHash() common.Hash {
	return st.bhash
}

func (st *StateDB) GetCode(addr common.Address) []byte {
	stateObject := st.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Code(st.db)
	}
	return nil
}
func (st *StateDB) GetCodeSize(addr common.Address) int {
	stateObject := st.getStateObject(addr)
	if stateObject == nil {
		return 0
	}
	if stateObject.code != nil {
		return len(stateObject.code)
	}
	size, err := st.db.ContractCodeSize(stateObject.addrHash, common.BytesToHash(stateObject.CodeHash()))
	if err != nil {
		st.setError(err)
	}
	return size
}

func (st *StateDB) GetCodeHash(addr common.Address) common.Hash {
	stateObject := st.getStateObject(addr)
	if stateObject == nil {
		return common.Hash{}
	}
	return common.BytesToHash(stateObject.CodeHash())
}

func (st *StateDB) GetState(addr common.Address, bhash common.Hash) common.Hash {
	stateObject := st.getStateObject(addr)
	if stateObject != nil {
		return stateObject.GetState(st.db, bhash)
	}
	return common.Hash{}
}

// GetProof returns the MerkleProof for a given Account
func (st *StateDB) GetProof(a common.Address) ([][]byte, error) {
	var proof proofList
	err := st.trie.Prove(crypto.Keccak256(a.Bytes()), 0, &proof)
	return [][]byte(proof), err
}

// GetProof returns the StorageProof for given key
func (st *StateDB) GetStorageProof(a common.Address, key common.Hash) ([][]byte, error) {
	var proof proofList
	sTrie := st.StorageTrie(a)
	if sTrie == nil {
		return proof, errors.New("storage trie for requested address does not exist")
	}
	err := sTrie.Prove(crypto.Keccak256(key.Bytes()), 0, &proof)
	return [][]byte(proof), err
}

// GetCommittedState retrieves a value from the given account's committed storage trie.
func (st *StateDB) GetCommittedState(addr common.Address, hash common.Hash) common.Hash {
	stateObject := st.getStateObject(addr)
	if stateObject != nil {
		return stateObject.GetCommittedState(st.db, hash)
	}
	return common.Hash{}
}

// Database retrieves the low level database supporting the lower level trie ops.
func (st *StateDB) Database() Database {
	return st.db
}

// StorageTrie returns the storage trie of an account.
// The return value is a copy and is nil for non-existent accounts.
func (st *StateDB) StorageTrie(addr common.Address) Trie {
	stateObject := st.getStateObject(addr)
	if stateObject == nil {
		return nil
	}
	cpy := stateObject.deepCopy(st)
	return cpy.updateTrie(st.db)
}

func (st *StateDB) HasSuicided(addr common.Address) bool {
	stateObject := st.getStateObject(addr)
	if stateObject != nil {
		return stateObject.suicided
	}
	return false
}

/*
 * SETTERS
 */

// AddBalance adds amount to the account associated with addr.
func (st *StateDB) AddBalance(addr common.Address, amount *big.Int) {
	stateObject := st.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.AddBalance(amount)
	}
}

// SubBalance subtracts amount from the account associated with addr.
func (st *StateDB) SubBalance(addr common.Address, amount *big.Int) {
	stateObject := st.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SubBalance(amount)
	}
}

func (st *StateDB) SetBalance(addr common.Address, amount *big.Int) {
	stateObject := st.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetBalance(amount)
	}
}

func (st *StateDB) SetNonce(addr common.Address, nonce uint64) {
	stateObject := st.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetNonce(nonce)
	}
}

func (st *StateDB) SetCode(addr common.Address, code []byte) {
	stateObject := st.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetCode(crypto.Keccak256Hash(code), code)
	}
}

func (st *StateDB) SetState(addr common.Address, key, value common.Hash) {
	stateObject := st.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetState(st.db, key, value)
	}
}

// Suicide marks the given account as suicided.
// This clears the account balance.
//
// The account's state object is still available until the state is committed,
// getStateObject will return a non-nil account after Suicide.
func (st *StateDB) Suicide(addr common.Address) bool {
	stateObject := st.getStateObject(addr)
	if stateObject == nil {
		return false
	}
	st.journal.append(suicideChange{
		account:     &addr,
		prev:        stateObject.suicided,
		prevbalance: new(big.Int).Set(stateObject.Balance()),
	})
	stateObject.markSuicided()
	stateObject.data.Balance = new(big.Int)

	return true
}

//
// Setting, updating & deleting state object methods.
//

// updateStateObject writes the given object to the trie.
func (st *StateDB) updateStateObject(stateObject *stateObject) {
	addr := stateObject.Address()
	data, err := rlp.EncodeToBytes(stateObject)
	if err != nil {
		panic(fmt.Errorf("can't encode object at %x: %v", addr[:], err))
	}
	st.setError(st.trie.TryUpdate(addr[:], data))
}

// deleteStateObject removes the given object from the state trie.
func (st *StateDB) deleteStateObject(stateObject *stateObject) {
	addr := stateObject.Address()
	st.setError(st.trie.TryDelete(addr[:]))
}

// Retrieve a state object given by the address. Returns nil if not found.
func (st *StateDB) getStateObject(addr common.Address) (stateObject *stateObject) {
	if obj := st.getDeletedStateObject(addr); obj != nil && !obj.deleted {
		return obj
	}
	return nil
}

// getDeletedStateObject is similar to getStateObject, but instead of returning
// nil for a deleted state object, it returns the actual object with the deleted
// flag set. This is needed by the state journal to revert to the correct s-
// destructed object instead of wiping all knowledge about the state object.
func (st *StateDB) getDeletedStateObject(addr common.Address) *stateObject {
	// Prefer live objects if any is available
	if obj := st.stateObjects[addr]; obj != nil {
		return obj
	}

	// Load the object from the database
	enc, err := st.trie.TryGet(addr[:])
	if len(enc) == 0 {
		st.setError(err)
		return nil
	}
	var data Account
	if err := rlp.DecodeBytes(enc, &data); err != nil {
		logging.Error("Failed to decode state object", "addr", addr, "err", err)
		return nil
	}
	// Insert into the live set
	obj := newObject(st, addr, data)
	st.setStateObject(obj)
	return obj
}

func (st *StateDB) setStateObject(object *stateObject) {
	st.stateObjects[object.Address()] = object
}

// Retrieve a state object or create a new state object if nil.
func (st *StateDB) GetOrNewStateObject(addr common.Address) *stateObject {
	stateObject := st.getStateObject(addr)
	if stateObject == nil {
		stateObject, _ = st.createObject(addr)
	}
	return stateObject
}

// createObject creates a new state object. If there is an existing account with
// the given address, it is overwritten and returned as the second return value.
func (st *StateDB) createObject(addr common.Address) (newobj, prev *stateObject) {
	prev = st.getDeletedStateObject(addr) // Note, prev might have been deleted, we need that!
	newobj = newObject(st, addr, Account{})
	newobj.setNonce(0) // sets the object to dirty

	if prev == nil {
		st.journal.append(createObjectChange{account: &addr})
	} else {
		st.journal.append(resetObjectChange{prev: prev})
	}

	st.setStateObject(newobj)
	return newobj, prev
}

// CreateAccount explicitly creates a state object. If a state object with the address
// already exists the balance is carried over to the new account.
//
// CreateAccount is called during the EVM CREATE operation. The situation might arise that
// a contract does the following:
//
//   1. sends funds to sha(account ++ (nonce + 1))
//   2. tx_create(sha(account ++ nonce)) (note that this gets the address of 1)
//
// Carrying over the balance ensures that Ether doesn't disappear.
func (st *StateDB) CreateAccount(addr common.Address) {
	newObj, prevObj := st.createObject(addr)
	if prevObj != nil {
		newObj.setBalance(prevObj.data.Balance)
	}
}

func (st *StateDB) ForEachStorage(addr common.Address, cb func(key, value common.Hash) bool) {
	so := st.getStateObject(addr)
	if so == nil {
		return
	}

	it := trie.NewIterator(so.getTrie(st.db).NodeIterator(nil))
	for it.Next() {
		key := common.BytesToHash(st.trie.GetKey(it.Key))
		if value, dirty := so.dirtyStorage[key]; dirty {
			if !cb(key, value) {
				return
			}
			continue
		}

		if len(it.Value) > 0 {
			_, content, _, err := rlp.Split(it.Value)
			if err != nil {
				return
			}
			if !cb(key, common.BytesToHash(content)) {
				return
			}
		}
	}
}

// Copy creates a deep, independent copy of the state.
// Snapshots of the copied state cannot be applied to the copy.
func (st *StateDB) Copy() *StateDB {
	//st.lock.Lock()
	//defer st.lock.Unlock()
	// Copy all the basic fields, initialize the memory ones
	state := &StateDB{
		db:                  st.db,
		trie:                st.db.CopyTrie(st.trie),
		stateObjects:        make(map[common.Address]*stateObject, len(st.journal.dirties)),
		stateObjectsPending: make(map[common.Address]struct{}, len(st.stateObjectsPending)),
		stateObjectsDirty:   make(map[common.Address]struct{}, len(st.journal.dirties)),

		valTrie:                st.db.CopyTrie(st.valTrie),
		validatorIndex:         st.validatorIndex.DeepCopy(),
		validatorObjects:       sync.Map{},
		validatorObjectsDirty:  make(map[common.Address]struct{}, len(st.validatorJournal.dirties)),
		validatorsStatModified: st.validatorsStatModified,

		stakingTrie:         st.db.CopyTrie(st.stakingTrie),
		stakingRecords:      make(map[biAddress]*stakingRecord),
		stakingRecordsDirty: make(map[biAddress]struct{}),
		pendingRelats:       st.pendingRelats.DeepCopy(),
		pendingRelatsDirty:  st.pendingRelatsDirty,

		refund:           st.refund,
		logs:             make(map[common.Hash][]*types.Log, len(st.logs)),
		logSize:          st.logSize,
		preimages:        make(map[common.Hash][]byte),
		journal:          newJournal(),
		validatorJournal: newJournal(),
	}
	// Copy the dirty states, logs, and preimages
	for addr := range st.journal.dirties {
		if object, exist := st.stateObjects[addr]; exist {
			state.stateObjects[addr] = object.deepCopy(state)
			state.stateObjectsDirty[addr] = struct{}{}
			state.stateObjectsPending[addr] = struct{}{} // Mark the copy pending to force external (account) commits
		}
	}
	// Above, we don't copy the actual journal. This means that if the copy is copied, the
	// loop above will be a no-op, since the copy's journal is empty.
	// Thus, here we iterate over stateObjects, to enable copies of copies
	for addr := range st.stateObjectsPending {
		if _, exist := state.stateObjects[addr]; !exist {
			state.stateObjects[addr] = st.stateObjects[addr].deepCopy(state)
		}
		state.stateObjectsPending[addr] = struct{}{}
	}
	for addr := range st.stateObjectsDirty {
		if _, exist := state.stateObjects[addr]; !exist {
			state.stateObjects[addr] = st.stateObjects[addr].deepCopy(state)
			state.stateObjectsDirty[addr] = struct{}{}
		}
	}

	for hash, logs := range st.logs {
		cpy := make([]*types.Log, len(logs))
		for i, l := range logs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		state.logs[hash] = cpy
	}

	for hash, preimage := range st.preimages {
		state.preimages[hash] = preimage
	}

	//region copy validator data
	for addr := range st.validatorJournal.dirties {
		if val, exist := st.validatorObjects.Load(addr); exist {
			state.validatorObjects.Store(addr, val.(*Validator).DeepCopy())
			state.validatorObjectsDirty[addr] = struct{}{}
		}
	}

	for mainAddress := range st.validatorObjectsDirty {
		if _, exist := state.validatorObjects.Load(mainAddress); !exist {
			val, _ := st.validatorObjects.Load(mainAddress)
			newVal := val.(*Validator).DeepCopy()
			state.validatorObjects.Store(mainAddress, newVal)
			state.validatorObjectsDirty[mainAddress] = struct{}{}
			state.validatorIndex.Add(mainAddress)
		}
	}

	if stat, err := st.getValidatorsStat(); err == nil {
		state.validatorsStat.Store(stat.DeepCopy())
	}

	if queue, err := st.getWithdrawQueue(); err == nil {
		state.withdrawQueue.Store(queue.DeepCopy())
	}
	//endregion

	//region copy staking data
	for key, value := range st.stakingRecords {
		state.stakingRecords[key] = value.DeepCopy()
	}
	for key, value := range st.stakingRecordsDirty {
		state.stakingRecordsDirty[key] = value
	}
	//endregion of copy staking data

	return state
}

// Snapshot returns an identifier for the current revision of the state.
func (st *StateDB) Snapshot() int {
	id := st.nextRevisionId
	st.nextRevisionId++
	st.validRevisions = append(st.validRevisions, revision{id, st.journal.length()})
	st.valValidRevisions = append(st.valValidRevisions, revision{id, st.validatorJournal.length()})
	return id
}

// RevertToSnapshot reverts all state changes made since the given revision.
func (st *StateDB) RevertToSnapshot(revid int) {
	// Find the snapshot in the stack of valid snapshots.
	idx := sort.Search(len(st.validRevisions), func(i int) bool {
		return st.validRevisions[i].id >= revid
	})
	if idx == len(st.validRevisions) || st.validRevisions[idx].id != revid {
		panic(fmt.Errorf("revision id %v cannot be reverted", revid))
	}
	snapshot := st.validRevisions[idx].journalIndex

	// Replay the journal to undo changes and remove invalidated snapshots
	st.journal.revert(st, snapshot) // 账户回滚

	// Find the snapshot in the stack of valid snapshots.
	valIdx := sort.Search(len(st.valValidRevisions), func(i int) bool {
		return st.valValidRevisions[i].id >= revid
	})
	if valIdx == len(st.valValidRevisions) || st.valValidRevisions[valIdx].id != revid {
		panic(fmt.Errorf("revision id %v cannot be reverted", revid))
	}
	valSnapshot := st.valValidRevisions[valIdx].journalIndex

	st.validatorJournal.revert(st, valSnapshot) // validator 回滚

	st.validRevisions = st.validRevisions[:idx]
	st.valValidRevisions = st.valValidRevisions[:idx]
}

// GetRefund returns the current value of the refund counter.
func (st *StateDB) GetRefund() uint64 {
	return st.refund
}

// Finalise finalises the state by removing the self destructed objects and clears the journal as well as the refunds.
func (st *StateDB) Finalise(deleteEmptyObjects bool) {
	for addr := range st.journal.dirties {
		stateObject, exist := st.stateObjects[addr]
		if !exist {
			continue
		}

		if stateObject.suicided || (deleteEmptyObjects && stateObject.empty()) {
			stateObject.deleted = true
		} else {
			stateObject.finalise()
		}
		st.stateObjectsPending[addr] = struct{}{}
		st.stateObjectsDirty[addr] = struct{}{}
	}

	// finalises validator objects
	for addr := range st.validatorJournal.dirties {
		_, exist := st.validatorObjects.Load(addr)
		if !exist {
			continue
		}
		st.validatorObjectsDirty[addr] = struct{}{}
	}

	// Invalidate journal because reverting across transactions is not allowed.
	st.clearJournalAndRefund()
}

// IntermediateRoot computes the current root hash of the state trie.
// It is called in between transactions to get the root hash that
// goes into transaction receipts.
func (st *StateDB) IntermediateRoot(deleteEmptyObjects bool) (common.Hash, common.Hash, common.Hash) {
	st.Finalise(deleteEmptyObjects)
	for addr := range st.stateObjectsPending {
		obj := st.stateObjects[addr]
		if obj.deleted {
			st.deleteStateObject(obj)
		} else {
			obj.updateRoot(st.db)
			st.updateStateObject(obj)
		}
	}
	if len(st.stateObjectsPending) > 0 {
		st.stateObjectsPending = make(map[common.Address]struct{})
	}

	// update val trie
	for addr := range st.validatorObjectsDirty {
		value, exist := st.validatorObjects.Load(addr)
		if !exist {
			continue
		}
		val := value.(*Validator)
		switch {
		case val.deleted || (deleteEmptyObjects && val.IsInvalid()):
			st.deleteValidator(val)
		default:
			st.updateValidator(val)
		}
	}
	if len(st.validatorObjectsDirty) > 0 {
		st.validatorObjectsDirty = make(map[common.Address]struct{})
	}

	if err := st.saveValidatorsIndex(); err != nil {
		logging.Error("save validator addresses failed", "err", err)
	}
	if err := st.saveValidatorsStat(); err != nil {
		logging.Error("save validators stat failed", "err", err)
	}
	if err := st.saveWithdrawQueue(); err != nil {
		logging.Error("save ubd queue failed", "err", err)
	}

	//update staking trie
	err := st.updateStakingTrie()
	if err != nil {
		logging.Error("updateStakingTrie failed", "err", err)
		st.setError(err)
	}
	return st.trie.Hash(), st.valTrie.Hash(), st.stakingTrie.Hash()
}

// Prepare sets the current transaction hash and index and block hash which is
// used when the EVM emits new state logs.
func (st *StateDB) Prepare(thash, bhash common.Hash, ti int) {
	st.thash = thash
	st.bhash = bhash
	st.txIndex = ti
}

func (st *StateDB) clearJournalAndRefund() {
	st.journal = newJournal()
	st.validatorJournal = newJournal()
	st.validRevisions = st.validRevisions[:0]
	st.refund = 0
}

// Commit writes the state to the underlying in-memory trie database.
func (st *StateDB) Commit(deleteEmptyObjects bool) (root, valRoot, stakingRoot common.Hash, err error) {
	// Finalize any pending changes and merge everything into the tries
	st.IntermediateRoot(deleteEmptyObjects)
	// Commit objects to the trie, measuring the elapsed time
	for addr := range st.stateObjectsDirty {
		if obj := st.stateObjects[addr]; !obj.deleted {
			// Write any contract code associated with the state object
			if obj.code != nil && obj.dirtyCode {
				st.db.TrieDB().InsertBlob(common.BytesToHash(obj.CodeHash()), obj.code)
				obj.dirtyCode = false
			}
			if obj.dirtyDlgs {
				if obj.GetDelegationsCount() > 0 {
					bs, err := rlp.EncodeToBytes(obj.Delegations())
					if err != nil {
						return common.Hash{}, common.Hash{}, common.Hash{}, err
					}
					st.db.TrieDB().InsertBlob(common.BytesToHash(obj.DelegationsHash()), bs)
				}
				obj.dirtyDlgs = false
			}
			// Write any storage changes in the state object to its storage trie
			if err := obj.CommitTrie(st.db); err != nil {
				return common.Hash{}, common.Hash{}, common.Hash{}, err
			}
		}
	}
	if len(st.stateObjectsDirty) > 0 {
		st.stateObjectsDirty = make(map[common.Address]struct{})
	}

	// Write trie changes.
	root, err = st.trie.Commit(func(leaf []byte, parent common.Hash) error {
		var account Account
		if err := rlp.DecodeBytes(leaf, &account); err != nil {
			return nil
		}
		if account.Root != emptyRoot {
			st.db.TrieDB().Reference(account.Root, parent)
		}
		code := common.BytesToHash(account.CodeHash)
		if code != emptyCode {
			st.db.TrieDB().Reference(code, parent)
		}
		if len(account.DelegationsHash) > 0 {
			dhash := common.BytesToHash(account.DelegationsHash)
			st.db.TrieDB().Reference(dhash, parent)
		}
		return nil
	})
	if err != nil {
		return
	}

	valRoot, err = st.valTrie.Commit(nil)
	if err != nil {
		return
	}

	stakingRoot, err = st.stakingTrie.Commit(nil)
	return root, valRoot, stakingRoot, err
}
