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
	"bytes"
	"errors"
	"fmt"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/trie"
	"math/big"
	"sync"
)

type ValidatorReader interface {
	GetValidatorsStat() (*ValidatorsStat, error)
	GetValidatorByMainAddr(mainAddress common.Address) *Validator
	GetValidators() *Validators
}

var (
	validatorFlag              = []byte(`valinfo-`) //valinfo- || mainAddress => rlp(validatorObject)
	validatorIndexFlag         = []byte("valindex") // valindex => rlp([addr1, addr2, ..., addrN])
	validatorStatFlag          = []byte("valstat")  // valstat => rlp([addr1, addr2, ..., addrN])
	validatorWithdrawQueueFlag = []byte("valubds")  // valubds => rlp([addr1, addr2, ..., addrN])
)

// NewVldReader create a new state that only with the given validator trie.
func NewVldReader(valRoot common.Hash, db Database, checkIntegrity bool) (ValidatorReader, error) {
	vtr, err := db.OpenTrie(valRoot)
	if err != nil {
		return nil, err
	}
	if checkIntegrity {
		it := trie.NewIterator(vtr.NodeIterator(nil))
		for it.Next() {
		}
		if it.Err != nil {
			return nil, it.Err
		}
	}

	st := &StateDB{
		db: db,

		valTrie:               vtr,
		validatorObjects:      sync.Map{},
		validatorIndex:        NewValidatorIndex(),
		validatorObjectsDirty: make(map[common.Address]struct{}),

		logs:             make(map[common.Hash][]*types.Log),
		preimages:        make(map[common.Hash][]byte),
		journal:          newJournal(),
		validatorJournal: newJournal(),
	}

	//load address list
	if err := st.getValidatorsIndex(); err != nil {
		logging.Error("load validator addresses failed", "err", err, "valRoot", valRoot.String())
		return nil, err
	}
	if _, err := st.getValidatorsStat(); err != nil {
		logging.Error("load validator stat failed", "err", err, "valRoot", valRoot.String())
		return nil, err
	}

	return st, nil
}

func (st *StateDB) UpdateValidator(newVal, oldVal *Validator) bool {
	if newVal == nil || oldVal == nil || (newVal.MainAddress() != oldVal.MainAddress()) { // validator address is
		return false
	}

	newMainAddress := newVal.MainAddress()
	st.setValidator(newVal)
	st.validatorJournal.append(validatorUpdateChange{address: &newMainAddress, newVal: newVal, oldVal: oldVal})

	if !newVal.StakeEqual(oldVal) {
		st.decrValidatorsStat(oldVal)
		st.incrValidatorsStat(newVal)
	}
	return true
}

func (st *StateDB) RemoveValidator(mainAddress common.Address) bool {
	value, ok := st.validatorObjects.Load(mainAddress)
	if !ok {
		return false
	}
	val := value.(*Validator)
	st.validatorJournal.append(validatorDeleteChange{address: &mainAddress, oldVal: val})
	val.deleted = true

	st.decrValidatorsStat(val)
	return true
}

func (st *StateDB) GetValidatorByMainAddr(mainAddress common.Address) *Validator {
	return st.getValidator(mainAddress)
}

func (st *StateDB) GetValidatorsStat() (*ValidatorsStat, error) {
	return st.getValidatorsStat()
}

func (st *StateDB) getValidatorsStat() (*ValidatorsStat, error) {
	if data := st.validatorsStat.Load(); data != nil {
		return data.(*ValidatorsStat), nil
	}
	if stat, err := st.loadValidatorsStat(); err != nil {
		logging.Error("loadValidatorsStat", "err", err)
		return stat, err
	} else {
		st.validatorsStat.Store(stat)
		return stat, nil
	}
}

// GetValidators 获取全部 validator 集合
// There's an in-memory cache for the results, so the results must be used as read-only.
func (st *StateDB) GetValidators() *Validators {
	if st.validatorIndex == nil || st.validatorIndex.Empty() {
		st.getValidatorsIndex()
	}
	st.loadAllValidators()

	set := st.validatorsSorted.Load()
	if set == nil {
		vals := []*Validator{}
		st.validatorObjects.Range(func(key, value interface{}) bool {
			if value != nil {
				vals = append(vals, value.(*Validator))
			}
			return true
		})
		newset := NewValidators(vals)
		st.validatorsSorted.Store(newset)
		return newset
	} else {
		return set.(*Validators)
	}
}

func (st *StateDB) GetValidatorsForUpdate() []*Validator {
	if st.validatorIndex == nil || st.validatorIndex.Empty() {
		st.getValidatorsIndex()
	}
	vals := make([]*Validator, 0)
	for _, addr := range st.validatorIndex.List() {
		val, exists := st.validatorObjects.Load(addr)
		if !exists {
			val = st.getValidator(addr)
			if val == nil {
				panic(fmt.Errorf("validator %s not exist", addr.String()))
			}
		}
		vals = append(vals, val.(*Validator))
	}
	return vals
}

// saveValidatorsIndex save all validator's address to in-memory trie
func (st *StateDB) saveValidatorsIndex() error {
	data, err := rlp.EncodeToBytes(st.validatorIndex)
	if err == nil {
		st.updateStakingData(common.Address{}, validatorIndexFlag, data)
	}
	logging.Trace("save validator index", "key", string(validatorIndexFlag), "data len", len(data))
	return err
}

// 	getValidatorsIndex return addresses of all validators
func (st *StateDB) getValidatorsIndex() error {
	var data []byte
	data, err := st.readStakingData(common.Address{}, validatorIndexFlag)
	if err != nil {
		st.setError(err)
		logging.Error("getValidatorsIndex readStakingData failed", "err", err)
		return err
	}

	if len(data) == 0 {
		return nil
	}

	index := NewValidatorIndex()
	if err := rlp.DecodeBytes(data, index); err != nil {
		logging.Error("NewValidatorIndex failed", "err", err, "data len", len(data))
		return err
	}
	st.validatorIndex = index
	return nil
}

func (st *StateDB) saveValidatorsStat() error {
	obj := st.validatorsStat.Load()
	var stat *ValidatorsStat
	if obj != nil {
		stat = obj.(*ValidatorsStat)
	} else {
		stat = NewValidatorsStat()
	}
	var (
		data []byte
		err  error
	)
	if data, err = rlp.EncodeToBytes(stat); err == nil {
		st.updateStakingData(common.Address{}, validatorStatFlag, data)
	} else {
		return err
	}
	return nil
}

func (st *StateDB) loadValidatorsStat() (*ValidatorsStat, error) {
	var data []byte
	data, err := st.readStakingData(common.Address{}, validatorStatFlag)
	if err != nil {
		return nil, err
	}

	stat := NewValidatorsStat()
	if len(data) == 0 {
		return stat, nil
	}

	if err := rlp.DecodeBytes(data, stat); err != nil {
		st.setError(err)
		return nil, err
	}
	return stat, nil
}

func (st *StateDB) loadAllValidators() error {
	for _, addr := range st.validatorIndex.List() {
		if _, exists := st.validatorObjects.Load(addr); !exists {
			val := st.getValidator(addr)
			if val == nil {
				return fmt.Errorf("validator %s not exist", addr.String())
			}
		}
	}
	return nil
}

func (st *StateDB) readStakingData(addr common.Address, flag []byte) ([]byte, error) {
	key := new(bytes.Buffer)
	key.Write(flag)
	if addr != (common.Address{}) {
		key.Write(addr.Bytes())
	}

	data, err := st.valTrie.TryGet(key.Bytes())
	if err != nil {
		st.setError(err)
		return nil, err
	}

	if len(data) < len(flag) {
		return nil, nil
	}

	if !bytes.HasPrefix(data, flag) {
		return nil, errors.New("validators stat data with malformed prefix")
	}
	return data[len(flag):], nil
}

func (st *StateDB) updateStakingData(addr common.Address, flag, data []byte) {
	buf := new(bytes.Buffer)
	buf.Write(flag)
	buf.Write(data)

	key := new(bytes.Buffer)
	key.Write(flag)
	if addr != (common.Address{}) {
		key.Write(addr.Bytes())
	}
	st.setError(st.valTrie.TryUpdate(key.Bytes(), buf.Bytes()))
}

func (st *StateDB) deleteStakingData(addr common.Address, flag []byte) {
	key := new(bytes.Buffer)
	key.Write(flag)
	if addr != (common.Address{}) {
		key.Write(addr.Bytes())
	}
	st.setError(st.valTrie.TryDelete(key.Bytes()))
}

func (st *StateDB) incrValidatorsStat(val *Validator) {
	if val == nil {
		return
	}
	stat, err := st.getValidatorsStat()
	if err != nil {
		return
	}
	// update stat
	stat.GetByRole(val.Role).AddVal(val)             // addCount(1).addStake(val.Stake).addToken(val.Token)             // 角色更新
	stat.GetByKind(val.Kind()).AddVal(val)           // addCount(1).addStake(val.Stake).addToken(val.Token)           // 分类更新
	stat.GetByKind(params.KindValidator).AddVal(val) // addCount(1).addStake(val.Stake).addToken(val.Token) // 全局数据更新
	st.validatorsStatModified = true
}

func (st *StateDB) decrValidatorsStat(val *Validator) {
	if val == nil {
		return
	}
	stat, err := st.getValidatorsStat()
	if err != nil {
		return
	}
	// update stat
	stat.GetByRole(val.Role).SubVal(val)             //subStake(val.Stake).subToken(val.Token).subCount(1)             // 角色更新
	stat.GetByKind(val.Kind()).SubVal(val)           //subStake(val.Stake).subToken(val.Token).subCount(1)           // 分类更新
	stat.GetByKind(params.KindValidator).SubVal(val) //.subStake(val.Stake).subToken(val.Token).subCount(1) // 全局数据更新
	st.validatorsStatModified = true
}

//
// Setting, updating & deleting validator object methods.
//

// updateValidator writes the given validator to the trie.
func (st *StateDB) updateValidator(val *Validator) {
	data, err := rlp.EncodeToBytes(val)
	if err != nil {
		panic(fmt.Errorf("can't encode object at %s: %v", val.MainAddress().String(), err))
	}

	mainAddress := val.MainAddress()
	st.updateStakingData(mainAddress, validatorFlag, data)
	st.validatorIndex.Add(mainAddress)
}

func (st *StateDB) deleteValidator(val *Validator) {
	val.deleted = true
	st.deleteStakingData(val.MainAddress(), validatorFlag)
	st.validatorIndex.Delete(val.MainAddress())
	st.decrValidatorsStat(val)
}

func (st *StateDB) getValidator(mainAddress common.Address) *Validator {
	// Prefer 'live' objects.
	if obj, ok := st.validatorObjects.Load(mainAddress); ok && obj != nil {
		val := obj.(*Validator)
		if val.deleted {
			logging.Error("validator deleted", "addr", mainAddress.String(), "val", val.MainAddress().String())
			return nil
		}
		return val
	}

	// Load the validator data from the database.
	enc, err := st.readStakingData(mainAddress, validatorFlag)
	if err != nil {
		st.setError(err)
		logging.Error("load staking data failed", "addr", mainAddress.String(), "err", err)
		return nil
	}
	if len(enc) == 0 {
		// not exist
		return nil
	}
	var data Validator
	if err := rlp.DecodeBytes(enc, &data); err != nil {
		logging.Error("Failed to decode validator data", "addr", mainAddress.String(), "err", err)
		return nil
	}

	st.setValidator(&data)
	return &data
}

func (st *StateDB) setValidator(val *Validator) {
	mainAddress := val.MainAddress()
	st.validatorObjects.Store(mainAddress, val)
	st.validatorIndex.Add(mainAddress)
}

func (st *StateDB) CreateValidator(name string, operator, coinbase common.Address, role params.ValidatorRole, mainPubKey, blsPubKey hexutil.Bytes, token, stake *big.Int, acceptDelegation, commissionRate, riskObligation uint16, status uint8) (newVal *Validator) {
	mainAddress := PubToAddress(mainPubKey)
	prev := st.getValidator(mainAddress)
	if prev != nil {
		return nil
	}

	newVal = NewValidator(name, operator, coinbase, role, mainPubKey, blsPubKey, token, stake, acceptDelegation, commissionRate, riskObligation, status)
	if newVal == nil {
		return nil
	}

	st.validatorJournal.append(validatorCreateChange{address: &mainAddress})
	st.setValidator(newVal)
	st.incrValidatorsStat(newVal)
	return newVal
}

func (st *StateDB) AddWithdrawRecord(record *WithdrawRecord) bool {
	queue, _ := st.getWithdrawQueue()
	queue.Add(record)
	st.validatorJournal.append(&validatorAddUBDChange{prev: record})
	return true
}

func (st *StateDB) GetWithdrawQueue() *WithdrawQueue {
	queue, _ := st.getWithdrawQueue()
	return queue
}

func (st *StateDB) RemoveWithdrawRecords(index []int) bool {
	queue, _ := st.getWithdrawQueue()
	removedRecords := queue.RemoveRecords(index)
	for _, record := range removedRecords {
		st.validatorJournal.append(&validatorDelWithdrawChange{address: &record.Validator, prev: record})
	}
	return true
}

func (st *StateDB) saveWithdrawQueue() error {
	queue, _ := st.getWithdrawQueue()
	if queue == nil {
		return nil
	}
	bs, err := rlp.EncodeToBytes(queue)
	if err != nil {
		return err
	}
	st.updateStakingData(common.Address{}, validatorWithdrawQueueFlag, bs)
	return nil
}

func (st *StateDB) revertWithdrawQueue(record *WithdrawRecord) {
	if queue, err := st.getWithdrawQueue(); err == nil && queue != nil && queue.Len() > 0 {
		queue.Delete(record)
	}
}

func (st *StateDB) getWithdrawQueue() (*WithdrawQueue, error) {
	if queue := st.withdrawQueue.Load(); queue != nil {
		return queue.(*WithdrawQueue), nil
	} else {
		data, err := st.readStakingData(common.Address{}, validatorWithdrawQueueFlag)
		queue := NewWithdrawQueue()
		st.withdrawQueue.Store(queue)
		if err != nil || len(data) == 0 {
			return queue, nil
		}
		if err := rlp.DecodeBytes(data, queue); err != nil {
			return queue, err
		} else {
			return queue, nil
		}
	}
}
