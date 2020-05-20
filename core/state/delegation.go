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
	"math/big"
	"sort"

	"github.com/youchainhq/go-youchain/common"
)

type DelegationFrom struct {
	Delegator common.Address `json:"delegator"`
	Stake     *big.Int       `json:"stake"`
	Token     *big.Int       `json:"token"`
}

func (d *DelegationFrom) DeepCopy() *DelegationFrom {
	return &DelegationFrom{
		Delegator: d.Delegator,
		Stake:     new(big.Int).Set(d.Stake),
		Token:     new(big.Int).Set(d.Token),
	}
}

func (d *DelegationFrom) Empty() bool {
	if d == nil {
		return true
	}
	return d.Stake.Sign() == 0 && d.Token.Sign() == 0
}

type DelegationFroms []*DelegationFrom

func (d DelegationFroms) Len() int { return len(d) }
func (d DelegationFroms) Less(i, j int) bool {
	return d[i].Delegator.Big().Cmp(d[j].Delegator.Big()) < 0
}
func (d DelegationFroms) Swap(i, j int) { d[i], d[j] = d[j], d[i] }

func (d DelegationFroms) Search(a common.Address) int {
	return sort.Search(len(d), func(i int) bool {
		return d[i].Delegator.Big().Cmp(a.Big()) >= 0
	})
}
func (d DelegationFroms) Exist(a common.Address) bool {
	i := d.Search(a)
	return i != d.Len() && d[i].Delegator == a
}

type DelegationTo struct {
	Validator common.Address `json:"validator"`
	Stake     *big.Int       `json:"stake"`
	Token     *big.Int       `json:"token"`
}
type DelegationTos []*DelegationTo
