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
	"errors"
	"fmt"
	"math/big"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/trie"
)

var (
	pendingRelationshipFlag = []byte(`pendingr`) // pendingr => rlp(biAddresses)
)

func (st *StateDB) loadPendingRelationship() error {
	data, err := st.readKeyedData(st.stakingTrie, pendingRelationshipFlag)
	if err != nil {
		return fmt.Errorf("read pending relationship data failed, err: %v", err)
	}
	p := newPendingRelationship()
	if len(data) > 0 {
		if err := rlp.DecodeBytes(data, p); err != nil {
			return err
		}
	}
	st.pendingRelats = p
	return nil
}
func (st *StateDB) readKeyedData(trie Trie, key []byte) ([]byte, error) {
	data, err := trie.TryGet(key)
	if err != nil {
		st.setError(err)
		return nil, err
	}

	if len(data) < len(key) {
		return nil, nil
	}

	if !bytes.HasPrefix(data, key) {
		return nil, errors.New("malformed prefix for keyed data")
	}
	return data[len(key):], nil
}

func (st *StateDB) updateKeyedData(trie Trie, key, data []byte) error {
	buf := new(bytes.Buffer)
	buf.Write(key)
	buf.Write(data)

	return trie.TryUpdate(key, buf.Bytes())
}

func (st *StateDB) deleteKeyedData(trie Trie, key []byte) {
	st.setError(trie.TryDelete(key))
}

// AddPendingRelationship adds a relationship to current staking trie
// Note: It's the caller's responsibility to make sure that
// the relationship is unique globally.
func (st *StateDB) AddPendingRelationship(d, v common.Address) {
	added := st.pendingRelats.Add(d, v)
	if added {
		st.pendingRelatsDirty = true
	}
}

func (st *StateDB) PendingRelationshipExist(d, v common.Address) bool {
	return st.pendingRelats.Exist(d, v)
}

func (st *StateDB) DelegatorPendingCount(d common.Address) int {
	return int(st.pendingRelats.DelegatorPendingCount(d))
}

func (st *StateDB) ValidatorPendingCount(v common.Address) int {
	return int(st.pendingRelats.ValidatorPendingCount(v))
}

func (st *StateDB) GetStakingRecordValue(d, v common.Address) *big.Int {
	key := newBiAddress(d, v)
	if obj := st.getStakingRecord(*key); obj != nil {
		return new(big.Int).Set(obj.Record().FinalValue)
	}
	return new(big.Int)
}

func (st *StateDB) AddStakingRecord(d, v common.Address, txHash common.Hash, newFinalValue *big.Int) {
	key := newBiAddress(d, v)
	sr := st.getOrNewStakingRecord(*key)
	if newFinalValue != nil {
		sr.record.FinalValue.Set(newFinalValue)
	}
	if txHash != (common.Hash{}) {
		sr.record.TxHashes = append(sr.record.TxHashes, txHash)
	}
	logging.Debug("AddStakingRecord", "key", hexutil.Encode(key[:]))
	st.stakingRecordsDirty[*key] = struct{}{}
}

func (st *StateDB) PendingValidatorExist(v common.Address) bool {
	key := newBiAddress(common.Address{}, v)
	if obj := st.getStakingRecord(*key); obj != nil {
		return true
	}
	return false
}

func (st *StateDB) getOrNewStakingRecord(key biAddress) *stakingRecord {
	if obj := st.getStakingRecord(key); obj != nil {
		return obj
	}
	obj := st.newStakingRecord(key)
	st.stakingRecords[key] = obj
	return obj
}

func (st *StateDB) getStakingRecord(key biAddress) *stakingRecord {
	// Prefer live objects if any is available
	if obj := st.stakingRecords[key]; obj != nil {
		return obj
	}

	// Load the object from the database
	enc, err := st.stakingTrie.TryGet(key[:])
	if len(enc) == 0 {
		st.setError(err)
		return nil
	}
	var data Record
	if err := rlp.DecodeBytes(enc, &data); err != nil {
		logging.Error("Failed to decode staking record", "key", hexutil.Encode(key[:]), "err", err)
		return nil
	}
	// Insert into the live set
	obj := &stakingRecord{
		record: data,
	}
	st.stakingRecords[key] = obj
	return obj
}

func (st *StateDB) newStakingRecord(key biAddress) *stakingRecord {
	return &stakingRecord{
		record: Record{
			FinalValue: new(big.Int),
		},
	}
}

func (st *StateDB) updateStakingTrie() error {
	//stakingRecords
	for key := range st.stakingRecordsDirty {
		sr := st.stakingRecords[key]
		data, err := rlp.EncodeToBytes(sr)
		if err != nil {
			return err
		}
		err = st.stakingTrie.TryUpdate(key[:], data)
		if err != nil {
			return err
		}
	}
	if len(st.stakingRecordsDirty) > 0 {
		st.stakingRecordsDirty = make(map[biAddress]struct{})
	}

	//pendingRelationship
	if st.pendingRelatsDirty {
		data, err := rlp.EncodeToBytes(&st.pendingRelats)
		if err != nil {
			return err
		}
		err = st.updateKeyedData(st.stakingTrie, pendingRelationshipFlag, data)
		if err != nil {
			return err
		}
		st.pendingRelatsDirty = false
	}
	return nil
}

func (st *StateDB) ForEachStakingRecord(cb func(d, v common.Address, record *Record) error) error {
	if len(st.stakingRecordsDirty) > 0 {
		if err := st.updateStakingTrie(); err != nil {
			return err
		}
	}
	it := trie.NewIterator(st.stakingTrie.NodeIterator(nil))
	for it.Next() {
		key := st.stakingTrie.GetKey(it.Key)
		// currently, it's safe to identify the stakingRecord key just by length,
		// because the only exception is the pendingRelationshipFlag.
		if len(key) != biAddressLen {
			continue
		}
		logging.Debug("iterate record", "key", hexutil.Encode(key[:]))
		d, v := common.BytesToAddress(key[:common.AddressLength]), common.BytesToAddress(key[common.AddressLength:])
		var data Record
		if err := rlp.DecodeBytes(it.Value, &data); err != nil {
			return fmt.Errorf("failed to decode staking record, key: %s err: %v", hexutil.Encode(key), err)
		}
		if err := cb(d, v, &data); err != nil {
			return err
		}
	}
	return nil
}

// UpdateDelegation will update both delegator and validator without any business check.
// returns newValidator,newDelegationFrom, stakeChanged, delegatorUpdateStatus
func (st *StateDB) UpdateDelegation(d common.Address, val *Validator, tokenChanged *big.Int) (*Validator, *DelegationFrom, *big.Int, params.CurdFlag) {
	if tokenChanged == nil || tokenChanged.Sign() == 0 {
		return val, nil, new(big.Int), params.Noop
	}
	dfrom := val.GetDelegationFrom(d)
	if dfrom == nil {
		// should be new add
		if tokenChanged.Sign() < 0 {
			return val, nil, new(big.Int), params.Noop
		}
		dfrom = &DelegationFrom{
			Delegator: d,
			Stake:     new(big.Int),
			Token:     new(big.Int),
		}
	}
	dfrom.Token.Add(dfrom.Token, tokenChanged)
	newStake := params.YOUToStake(dfrom.Token)
	delta := new(big.Int).Sub(newStake, dfrom.Stake)
	dfrom.Stake.Set(newStake)

	newVal := val.PartialCopy()
	newVal.Token.Add(newVal.Token, tokenChanged)
	newVal.Stake.Add(newVal.Stake, delta)

	status := newVal.UpdateDelegationFrom(dfrom)
	st.UpdateValidator(newVal, val)
	st.UpdateDelegator(d, val.MainAddress(), tokenChanged, status == params.Delete)
	return newVal, dfrom, delta, status
}

// stateObject related

// UpdateDelegator updates delegations index for an account,
// `delta` is the delegation amount current added (when delta is positive) or subtracted (when delta is negative).
func (st *StateDB) UpdateDelegator(addr, toValidator common.Address, delta *big.Int, delete bool) {
	obj := st.getStateObject(addr)
	if obj == nil {
		// actually this SHOULD NOT happened unless there's db error
		if err := st.Error(); err != nil {
			logging.Error("unexpected db error", "err", err)
		}
		return
	}

	obj.UpdateDelegationTo(toValidator, delete)

	obj.AddDelegationBalance(delta)
}

// GetCountOfDelegateTo gets a delegator address,
// returns how many validators it has delegation to.
func (st *StateDB) GetCountOfDelegateTo(d common.Address) int {
	obj := st.getStateObject(d)
	if obj == nil {
		return 0
	}
	return obj.GetDelegationsCount()
}

func (st *StateDB) GetDelegationsFrom(d common.Address) ([]*DelegationTo, error) {
	obj := st.getStateObject(d)
	if obj == nil {
		return nil, nil
	}
	dtos := make([]*DelegationTo, 0, obj.GetDelegationsCount())
	for _, vaddr := range obj.Delegations() {
		v := st.GetValidatorByMainAddr(vaddr)
		if v == nil {
			return nil, fmt.Errorf("THIS SHOULD BE A BUG. get delegation error, validator of %s not exist", vaddr.String())
		}
		df := v.GetDelegationFrom(d)
		if df == nil {
			return nil, fmt.Errorf("THIS SHOULD BE A BUG. validator %s do not have delegation from %s ", vaddr.String(), d.String())
		}
		dtos = append(dtos, &DelegationTo{
			Validator: vaddr,
			Stake:     df.Stake,
			Token:     df.Token,
		})
	}
	return dtos, nil
}
