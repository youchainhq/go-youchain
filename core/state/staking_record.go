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
	"io"
	"math/big"
	"sort"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/rlp"
)

const biAddressLen = 2 * common.AddressLength

type stakingRecord struct {
	record Record
}

type Record struct {
	FinalValue *big.Int
	TxHashes   []common.Hash
}

// Record returns the actual record for read
func (sr *stakingRecord) Record() Record {
	return sr.record
}

// EncodeRLP implements rlp.Encoder.
func (sr *stakingRecord) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, sr.record)
}

func (sr *stakingRecord) DeepCopy() *stakingRecord {
	cpy := &stakingRecord{
		record: Record{
			FinalValue: new(big.Int).Set(sr.record.FinalValue),
			TxHashes:   make([]common.Hash, len(sr.record.TxHashes)),
		},
	}
	if len(sr.record.TxHashes) > 0 {
		copy(cpy.record.TxHashes, sr.record.TxHashes)
	}
	return cpy
}

// delegatorAddress|validatorAddress
type biAddress [biAddressLen]byte

func newBiAddress(d, v common.Address) *biAddress {
	var bi biAddress
	copy(bi[:common.AddressLength], d[:])
	copy(bi[common.AddressLength:], v[:])
	return &bi
}
func (bi *biAddress) Split() (d, v common.Address) {
	return common.BytesToAddress(bi[:common.AddressLength]), common.BytesToAddress(bi[common.AddressLength:])
}

type biAddresses []*biAddress

func (b biAddresses) Len() int { return len(b) }
func (b biAddresses) Less(i, j int) bool {
	return bytes.Compare(b[i][:], b[j][:]) < 0
}
func (b biAddresses) Swap(i, j int) { b[i], b[j] = b[j], b[i] }

func (b biAddresses) Search(a biAddress) int {
	return sort.Search(len(b), func(i int) bool {
		return bytes.Compare(b[i][:], a[:]) >= 0
	})
}
func (b biAddresses) Exist(d, v common.Address) bool {
	a := newBiAddress(d, v)
	i := b.Search(*a)
	return i != b.Len() && bytes.Compare(b[i][:], a[:]) == 0
}

// pendingRelationship records the current unique pending delegation relationship between delegator and validator
type pendingRelationship struct {
	r biAddresses

	delegatorPendingCount map[common.Address]uint16
	validatorPendingCount map[common.Address]uint16
}

func newPendingRelationship() *pendingRelationship {
	return &pendingRelationship{
		r:                     biAddresses{},
		delegatorPendingCount: make(map[common.Address]uint16),
		validatorPendingCount: make(map[common.Address]uint16),
	}
}

func (p *pendingRelationship) Exist(d, v common.Address) bool {
	return p.r.Exist(d, v)
}

//Add adds the (d,v) to pending relationship when it does not exist!
// the return value indicates whether it's been added or not.
func (p *pendingRelationship) Add(d, v common.Address) bool {
	a := newBiAddress(d, v)
	i := p.r.Search(*a)
	if i == p.r.Len() || bytes.Compare(p.r[i][:], a[:]) != 0 {
		oldLen := p.r.Len()
		p.r = append(p.r, a)
		if i < oldLen {
			// adjust the position
			copy(p.r[i+1:], p.r[i:oldLen])
			p.r[i] = a
		}
		p.delegatorPendingCount[d]++
		p.validatorPendingCount[v]++
		return true
	}
	return false
}

func (p *pendingRelationship) DelegatorPendingCount(d common.Address) uint16 {
	return p.delegatorPendingCount[d]
}
func (p *pendingRelationship) ValidatorPendingCount(v common.Address) uint16 {
	return p.validatorPendingCount[v]
}

func (p *pendingRelationship) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, p.r)
}
func (p *pendingRelationship) DecodeRLP(s *rlp.Stream) error {
	var r biAddresses
	if err := s.Decode(&r); err != nil {
		return err
	}
	p.r = r
	for _, bi := range r {
		d, v := bi.Split()
		p.delegatorPendingCount[d]++
		p.validatorPendingCount[v]++
	}
	return nil
}

func (p *pendingRelationship) DeepCopy() *pendingRelationship {
	cpy := &pendingRelationship{
		r:                     make(biAddresses, p.r.Len()),
		delegatorPendingCount: make(map[common.Address]uint16),
		validatorPendingCount: make(map[common.Address]uint16),
	}
	for i, value := range p.r {
		vCpy := *value
		cpy.r[i] = &vCpy
	}
	for key, value := range p.delegatorPendingCount {
		cpy.delegatorPendingCount[key] = value
	}
	for key, value := range p.validatorPendingCount {
		cpy.validatorPendingCount[key] = value
	}
	return cpy
}
