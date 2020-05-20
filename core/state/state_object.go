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

package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/rlp"
	"io"
	"math/big"
)

var emptyCodeHash = crypto.Keccak256(nil)

type Code []byte

func (c Code) String() string {
	return string(c) //strings.Join(Disassemble(c), " ")
}

type Storage map[common.Hash]common.Hash

func (s Storage) String() (str string) {
	for key, value := range s {
		str += fmt.Sprintf("%X : %X\n", key, value)
	}

	return
}

func (s Storage) Copy() Storage {
	cpy := make(Storage)
	for key, value := range s {
		cpy[key] = value
	}

	return cpy
}

// stateObject represents an Ethereum account which is being modified.
//
// The usage pattern is as follows:
// First you need to obtain a state object.
// Account values can be accessed and modified through the object.
// Finally, call CommitTrie to write the modified storage trie into a database.
type stateObject struct {
	address  common.Address
	addrHash common.Hash // hash of ethereum address of the account
	data     Account
	db       *StateDB

	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be returned
	// by StateDB.Commit.
	dbErr error

	// Write caches.
	trie Trie // storage trie, which becomes non-nil on first access
	code Code // contract bytecode, which gets set when code is loaded

	originStorage  Storage // Storage cache of original entries to dedup rewrites, reset for every transaction
	pendingStorage Storage // Storage entries that need to be flushed to disk, at the end of an entire block
	dirtyStorage   Storage // Storage entries that need to be flushed to disk

	// Cache flags.
	// When an object is marked suicided it will be delete from the trie
	// during the "update" phase of the state transition.
	dirtyCode bool // true if the code was updated
	suicided  bool
	deleted   bool

	// validator addresses to which this account has a delegation
	delegations common.SortedAddresses
	dirtyDlgs   bool // true if the delegations was updated
}

// empty returns whether the account is considered empty.
func (so *stateObject) empty() bool {
	return so.data.Nonce == 0 && so.data.Balance.Sign() == 0 && bytes.Equal(so.data.CodeHash, emptyCodeHash)
}

// Account is the Ethereum consensus representation of accounts.
// These objects are stored in the main account trie.
type Account struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash // merkle root of the storage trie
	CodeHash []byte

	DelegationBalance *big.Int
	DelegationsHash   []byte
}

// newObject creates a state object.
func newObject(db *StateDB, address common.Address, data Account) *stateObject {
	if data.Balance == nil {
		data.Balance = new(big.Int)
	}
	if data.CodeHash == nil {
		data.CodeHash = emptyCodeHash
	}
	if data.DelegationBalance == nil {
		data.DelegationBalance = new(big.Int)
	}

	return &stateObject{
		db:             db,
		address:        address,
		addrHash:       crypto.Keccak256Hash(address[:]),
		data:           data,
		originStorage:  make(Storage),
		pendingStorage: make(Storage),
		dirtyStorage:   make(Storage),
	}
}

// EncodeRLP implements rlp.Encoder.
func (so *stateObject) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, so.data)
}

// setError remembers the first non-nil error it is called with.
func (so *stateObject) setError(err error) {
	if so.dbErr == nil {
		so.dbErr = err
	}
}

func (so *stateObject) markSuicided() {
	so.suicided = true
}

func (so *stateObject) touch() {
	so.db.journal.append(touchChange{
		account: &so.address,
	})
	if so.address == ripemd {
		// Explicitly put it in the dirty-cache, which is otherwise generated from
		// flattened journals.
		so.db.journal.dirty(so.address)
	}
}

func (so *stateObject) getTrie(db Database) Trie {
	if so.trie == nil {
		var err error
		so.trie, err = db.OpenStorageTrie(so.addrHash, so.data.Root)
		if err != nil {
			so.trie, _ = db.OpenStorageTrie(so.addrHash, common.Hash{})
			so.setError(fmt.Errorf("can't create storage trie: %v", err))
		}
	}
	return so.trie
}

// GetState returns a value in account storage.
func (so *stateObject) GetState(db Database, key common.Hash) common.Hash {
	// If we have a dirty value for this state entry, return it
	value, dirty := so.dirtyStorage[key]
	if dirty {
		return value
	}
	// Otherwise return the entry's original value
	return so.GetCommittedState(db, key)
}

// GetCommittedState retrieves a value from the committed account storage trie.
func (so *stateObject) GetCommittedState(db Database, key common.Hash) common.Hash {
	// If we have a pending write or clean cached, return that
	if value, pending := so.pendingStorage[key]; pending {
		return value
	}
	if value, cached := so.originStorage[key]; cached {
		return value
	}

	// Otherwise load the value from the database
	enc, err := so.getTrie(db).TryGet(key[:])
	if err != nil {
		so.setError(err)
		return common.Hash{}
	}
	var value common.Hash
	if len(enc) > 0 {
		_, content, _, err := rlp.Split(enc)
		if err != nil {
			so.setError(err)
		}
		value.SetBytes(content)
	}
	so.originStorage[key] = value
	return value
}

// SetState updates a value in account storage.
func (so *stateObject) SetState(db Database, key, value common.Hash) {
	// If the new value is the same as old, don't set
	prev := so.GetState(db, key)
	if prev == value {
		return
	}
	so.db.journal.append(storageChange{
		account:  &so.address,
		key:      key,
		prevalue: prev,
	})
	so.setState(key, value)
}

func (so *stateObject) setState(key, value common.Hash) {
	so.dirtyStorage[key] = value
}

// finalise moves all dirty storage slots into the pending area to be hashed or
// committed later. It is invoked at the end of every transaction.
func (so *stateObject) finalise() {
	for key, value := range so.dirtyStorage {
		so.pendingStorage[key] = value
	}
	if len(so.dirtyStorage) > 0 {
		so.dirtyStorage = make(Storage)
	}
}

// updateTrie writes cached storage modifications into the object's storage trie.
func (so *stateObject) updateTrie(db Database) Trie {
	// Make sure all dirty slots are finalized into the pending storage area
	so.finalise()

	// Insert all the pending updates into the trie
	tr := so.getTrie(db)
	for key, value := range so.pendingStorage {
		// Skip noop changes, persist actual changes
		if value == so.originStorage[key] {
			continue
		}
		so.originStorage[key] = value

		if (value == common.Hash{}) {
			so.setError(tr.TryDelete(key[:]))
			continue
		}
		// Encoding []byte cannot fail, ok to ignore the error.
		v, _ := rlp.EncodeToBytes(common.TrimLeftZeroes(value[:]))
		so.setError(tr.TryUpdate(key[:], v))
	}
	if len(so.pendingStorage) > 0 {
		so.pendingStorage = make(Storage)
	}
	return tr
}

// UpdateRoot sets the trie root to the current root hash of
func (so *stateObject) updateRoot(db Database) {
	so.updateTrie(db)
	so.data.Root = so.trie.Hash()
}

// CommitTrie the storage trie of the object to db.
// This updates the trie root.
func (so *stateObject) CommitTrie(db Database) error {
	so.updateTrie(db)
	if so.dbErr != nil {
		return so.dbErr
	}
	root, err := so.trie.Commit(nil)
	if err == nil {
		so.data.Root = root
	}
	return err
}

// AddBalance removes amount from c's balance.
// It is used to add funds to the destination account of a transfer.
func (so *stateObject) AddBalance(amount *big.Int) {
	// We must check emptiness for the objects such that the account
	// clearing (0,0,0 objects) can take effect.
	if amount.Sign() == 0 {
		if so.empty() {
			so.touch()
		}

		return
	}
	so.SetBalance(new(big.Int).Add(so.Balance(), amount))
}

// SubBalance removes amount from c's balance.
// It is used to remove funds from the origin account of a transfer.
func (so *stateObject) SubBalance(amount *big.Int) {
	if amount.Sign() == 0 {
		return
	}
	so.SetBalance(new(big.Int).Sub(so.Balance(), amount))
}

func (so *stateObject) SetBalance(amount *big.Int) {
	so.db.journal.append(balanceChange{
		account: &so.address,
		prev:    new(big.Int).Set(so.data.Balance),
	})
	so.setBalance(amount)
}

func (so *stateObject) setBalance(amount *big.Int) {
	so.data.Balance = amount
}

// Return the gas back to the origin. Used by the Virtual machine or Closures
func (so *stateObject) ReturnGas(gas *big.Int) {}

func (so *stateObject) deepCopy(db *StateDB) *stateObject {
	stateObject := newObject(db, so.address, so.data)
	if so.trie != nil {
		stateObject.trie = db.db.CopyTrie(so.trie)
	}
	stateObject.code = so.code
	stateObject.dirtyStorage = so.dirtyStorage.Copy()
	stateObject.originStorage = so.originStorage.Copy()
	stateObject.pendingStorage = so.pendingStorage.Copy()
	stateObject.suicided = so.suicided
	stateObject.dirtyCode = so.dirtyCode
	stateObject.deleted = so.deleted
	return stateObject
}

//
// Attribute accessors
//

// Returns the address of the contract/account
func (so *stateObject) Address() common.Address {
	return so.address
}

// Code returns the contract code associated with this object, if any.
func (so *stateObject) Code(db Database) []byte {
	if so.code != nil {
		return so.code
	}
	if bytes.Equal(so.CodeHash(), emptyCodeHash) {
		return nil
	}
	code, err := db.ContractCode(so.addrHash, common.BytesToHash(so.CodeHash()))
	if err != nil {
		so.setError(fmt.Errorf("can't load code hash %x: %v", so.CodeHash(), err))
	}
	so.code = code
	return code
}

func (so *stateObject) SetCode(codeHash common.Hash, code []byte) {
	prevcode := so.Code(so.db.db)
	so.db.journal.append(codeChange{
		account:  &so.address,
		prevhash: so.CodeHash(),
		prevcode: prevcode,
	})
	so.setCode(codeHash, code)
}

func (so *stateObject) setCode(codeHash common.Hash, code []byte) {
	so.code = code
	so.data.CodeHash = codeHash[:]
	so.dirtyCode = true
}

func (so *stateObject) SetNonce(nonce uint64) {
	so.db.journal.append(nonceChange{
		account: &so.address,
		prev:    so.data.Nonce,
	})
	so.setNonce(nonce)
}

func (so *stateObject) setNonce(nonce uint64) {
	so.data.Nonce = nonce
}

func (so *stateObject) CodeHash() []byte {
	return so.data.CodeHash
}

func (so *stateObject) Balance() *big.Int {
	return so.data.Balance
}

func (so *stateObject) Nonce() uint64 {
	return so.data.Nonce
}

// Never called, but must be present to allow stateObject to be used
// as a vm.Account interface that also satisfies the vm.ContractRef
// interface. Interfaces are awesome.
func (so *stateObject) Value() *big.Int {
	panic("Value on stateObject should never be called")
}

func (so *stateObject) DelegationsHash() []byte {
	return so.data.DelegationsHash
}

func (so *stateObject) DelegationBalance() *big.Int {
	return so.data.DelegationBalance
}

func (so *stateObject) AddDelegationBalance(value *big.Int) {
	so.SetDelegationBalance(new(big.Int).Add(so.DelegationBalance(), value))
}

func (so *stateObject) SubDelegationBalance(value *big.Int) {
	so.SetDelegationBalance(new(big.Int).Sub(so.DelegationBalance(), value))
}

func (so *stateObject) SetDelegationBalance(value *big.Int) {
	so.db.journal.append(delegationBalanceChange{
		account: &so.address,
		prev:    new(big.Int).Set(so.data.DelegationBalance),
	})
	so.setDelegationBalance(value)
}

func (so *stateObject) setDelegationBalance(value *big.Int) {
	so.data.DelegationBalance = value
}

func (so *stateObject) UpdateDelegationTo(validator common.Address, delete bool) {
	so.loadDelegations()
	i := so.delegations.Search(validator)
	if i == so.delegations.Len() || so.delegations[i] != validator {
		//not found
		if delete {
			return
		}
		// get a new copy for updating
		newCopy := make(common.SortedAddresses, so.delegations.Len())
		if so.delegations.Len() > 0 {
			copy(newCopy, so.delegations)
		}
		// update the slice
		newCopy = append(newCopy, validator)
		if newCopy[i] != validator {
			// adjust the position
			copy(newCopy[i+1:], newCopy[i:newCopy.Len()-1])
			newCopy[i] = validator
		}
		// do final update
		so.updateDelegations(newCopy)
	} else if delete {
		newCopy := make(common.SortedAddresses, so.delegations.Len())
		copy(newCopy, so.delegations)
		oldLen := newCopy.Len()
		copy(newCopy[i:oldLen-1], newCopy[i+1:])
		newCopy = newCopy[:oldLen-1]
		so.updateDelegations(newCopy)
	}
}

func (so *stateObject) updateDelegations(dlgs common.SortedAddresses) {
	so.db.journal.append(delegationsChange{
		account:  &so.address,
		prevdlgs: so.delegations,
		prevhash: so.DelegationsHash(),
	})
	so.dirtyDlgs = true
	var hash []byte
	if dlgs.Len() > 0 {
		bs, err := rlp.EncodeToBytes(dlgs)
		if err != nil { // SHOULD NOT HAPPENED
			j, _ := json.Marshal(dlgs)
			panic(fmt.Sprintf("rlp encode common.SortedAddresses error, data=%s  err =%v\n", string(j), err))
		}
		hash = crypto.Keccak256Hash(bs).Bytes()
	}
	so.setDelegations(hash, dlgs)
}

func (so *stateObject) setDelegations(hash []byte, dlgs common.SortedAddresses) {
	so.data.DelegationsHash = hash
	so.delegations = dlgs
}

func (so *stateObject) GetDelegationsCount() int {
	return so.Delegations().Len()
}

func (so *stateObject) Delegations() common.SortedAddresses {
	so.loadDelegations()
	return so.delegations
}

func (so *stateObject) loadDelegations() {
	if so.delegations != nil {
		return
	}
	if len(so.DelegationsHash()) == 0 {
		so.delegations = make(common.SortedAddresses, 0)
		return
	}
	dlgs := new(common.SortedAddresses)
	// SHOULD NOT has any error
	bs, err := so.db.db.TrieDB().Node(common.BytesToHash(so.DelegationsHash()))
	if err != nil {
		panic("load delegations error: " + err.Error())
	}
	if err = rlp.DecodeBytes(bs, dlgs); err != nil {
		panic("decode delegations error: " + err.Error())
	}
	so.delegations = *dlgs
}
