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
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"math/big"
	"sort"
	"testing"
)

var (
	pk1    = hexutil.Bytes(common.FromHex(`0x8519dda01d49f3ed67ad2d745c8ba5b4a098a50fe527c86826afda985b35a8de`))
	addr   = common.HexToAddress(`0x9Cc3B43C80A6AE79A8714Bb230dbdE472B40278b`)
	valSrc *Validator
)

func init() {
	token := new(big.Int).Mul(big.NewInt(10000000000), params.StakeUint)
	valSrc = NewValidator("", addr, addr, params.RoleChancellor, pk1, pk1, token, big.NewInt(10000000000), params.AcceptDelegation, 2000, 1000, params.ValidatorOnline)
	valSrc.Delegations = append(valSrc.Delegations, &DelegationFrom{
		Delegator: common.Address{0x11},
		Stake:     big.NewInt(10),
		Token:     big.NewInt(10),
	})
	valSrc.UpdateLastActive(123456)
}

func TestValidatorJsonEncode(t *testing.T) {
	bs, err := json.Marshal(valSrc)
	assert.NoError(t, err, "json encode failed")
	t.Log(string(bs))
	val2 := Validator{}
	err = json.Unmarshal(bs, &val2)
	assert.NoError(t, err, "json decode failed")
	assert.Equal(t, valSrc.MainAddress(), val2.MainAddress())
	assert.Equal(t, 0, valSrc.Token.Cmp(val2.Token))
	assert.Equal(t, valSrc.LastActive(), val2.LastActive())
}

func TestValidatorEncode(t *testing.T) {
	bs, err := rlp.EncodeToBytes(valSrc)
	require.NoError(t, err)
	valDesc := Validator{}
	err = rlp.DecodeBytes(bs, &valDesc)
	require.NoError(t, err, "")
	bs2, err := rlp.EncodeToBytes(&valDesc)
	require.NoError(t, err)
	require.True(t, bytes.Equal(bs, bs2))
	assert.Equal(t, valSrc.LastActive(), valDesc.LastActive())
}

func TestDeepCopy(t *testing.T) {
	valDest := valSrc.PartialCopy()
	assert.NotEqual(t, fmt.Sprintf("%p", valSrc), fmt.Sprintf("%p", valDest))
	valDest.Stake = big.NewInt(123456789)
	valDest.Token = big.NewInt(123456789)
	assert.NotEqual(t, valSrc.Stake.Cmp(valDest.Stake), 0)
}

func TestValidators_Remove(t *testing.T) {
	num := 11
	vals := []*Validator{}
	for i := 0; i < num; i++ {
		valCopy := valSrc.DeepCopy()
		valCopy.Stake = big.NewInt(0).Add(valCopy.Stake, big.NewInt(10000*int64(i)))
		vals = append(vals, valCopy)
	}
	valSet := NewValidators(vals)

	var (
		removeAddr         = common.BigToAddress(big.NewInt(0))
		removeNotExistAddr = common.BigToAddress(big.NewInt(110))
		succ               bool
		expectNum          = 10
	)
	succ = valSet.Remove(removeAddr)
	assert.True(t, succ)
	assert.Equal(t, expectNum, valSet.Len())

	succ = valSet.Remove(removeNotExistAddr)
	assert.False(t, succ)
	assert.Equal(t, expectNum, valSet.Len())
}

func TestNewValidators(t *testing.T) {
	const num = 10
	vals := [num]*Validator{}
	keys := [num]*ecdsa.PrivateKey{}
	addrs := [num]*common.Address{}

	for i := 0; i < num; i++ {
		key, _ := crypto.GenerateKey()
		keys[i] = key
		pk := crypto.CompressPubkey(&key.PublicKey)
		addr := crypto.PubkeyToAddress(key.PublicKey)
		addrs[i] = &addr
		vals[i] = NewValidator(addr.String(), addr, addr, params.RoleChancellor, pk, pk, big.NewInt(int64(10000+i*10)), big.NewInt(int64(10000+i*10)), params.AcceptDelegation, 2000, 1000, params.ValidatorOnline)
	}

	valSet := NewValidators(vals[:])

	idx1, _ := valSet.GetIndex(*addrs[1])
	val1, _ := valSet.GetByIndex(idx1)
	assert.Equal(t, *addrs[1], val1.MainAddress())

	for i := 0; i < num-1; i++ {
		a, _ := valSet.GetByIndex(i)
		b, _ := valSet.GetByIndex(i + 1)
		assert.True(t, a.Stake.Cmp(b.Stake) >= 0)
	}

	assert.True(t, sort.IsSorted(sort.Reverse(valSet)))
}

func TestValidatorsStat_EncodeRLP(t *testing.T) {
	stat := NewValidatorsStat()
	{
		statOfKind := stat.GetByKind(params.KindValidator)
		statOfKind.addStake(big.NewInt(1000)).addCount(10).AddRewards(big.NewInt(100))
	}
	{
		statOfKind := stat.GetByKind(params.KindChamber)
		statOfKind.addStake(big.NewInt(2000)).addCount(10).AddRewards(big.NewInt(100))
	}
	{
		statOfKind := stat.GetByKind(params.KindHouse)
		statOfKind.addStake(big.NewInt(3000)).addCount(10).AddRewards(big.NewInt(100))
	}

	bs, err := rlp.EncodeToBytes(&stat)
	assert.Nil(t, err)
	stat2 := NewValidatorsStat()
	err = rlp.DecodeBytes(bs, stat2)
	assert.Nil(t, err)

	bs, _ = json.Marshal(stat2)
	assert.Equal(t, stat.GetStakeByKind(params.KindHouse).Int64(), stat2.GetStakeByKind(params.KindHouse).Int64())
	assert.Equal(t, stat.GetStakeByKind(params.KindChamber).Int64(), stat2.GetStakeByKind(params.KindChamber).Int64())
	assert.Equal(t, stat.GetStakeByKind(params.KindValidator).Int64(), stat2.GetStakeByKind(params.KindValidator).Int64())
}

func TestNewWithdrawQueue(t *testing.T) {
	q := NewWithdrawQueue()
	bs, err := rlp.EncodeToBytes(q)
	assert.Nil(t, err)

	for i := 0; i < 100; i++ {
		q.Add(&WithdrawRecord{
			Validator:        common.BigToAddress(big.NewInt(int64(0x100000 + i))),
			Operator:         common.BigToAddress(big.NewInt(int64(0x200000 + i))),
			Recipient:        common.BigToAddress(big.NewInt(int64(0x200000 + i))),
			CreationHeight:   10,
			CompletionHeight: 100,
			InitialBalance:   big.NewInt(1000),
			FinalBalance:     big.NewInt(0),
			Finished:         0,
		})
	}
	bs, err = rlp.EncodeToBytes(q)
	assert.Nil(t, err)
	q2 := WithdrawQueue{}
	err = rlp.DecodeBytes(bs, &q2)
	assert.Nil(t, err)
	assert.Equal(t, common.BigToAddress(big.NewInt(int64(0x100000+10))).String(), q2.Records[10].Validator.String())
	assert.Equal(t, common.BigToAddress(big.NewInt(int64(0x200000+10))).String(), q2.Records[10].Operator.String())
	assert.Equal(t, common.BigToAddress(big.NewInt(int64(0x200000+10))).String(), q2.Records[10].Recipient.String())

	q2.RemoveRecords([]int{10})

	assert.Equal(t, 99, q2.Len())
	assert.Equal(t, 100, q.Len())
}

func TestValidatorAddressIndex(t *testing.T) {
	rawIndex := NewValidatorIndex()
	for i := 0; i < 10; i++ {
		addr := common.BigToAddress(big.NewInt(int64(i)))
		rawIndex.Add(addr)
	}

	encodeBytes, err := rlp.EncodeToBytes(rawIndex)
	assert.NoError(t, err)
	decIndex := NewValidatorIndex()
	err = rlp.DecodeBytes(encodeBytes, decIndex)
	assert.NoError(t, err)
	assert.Equal(t, 10, len(decIndex.List()))

	rawList := rawIndex.List()
	decList := decIndex.List()
	for i := 0; i < 10; i++ {
		assert.Equal(t, rawList[i], decList[i])
	}

	decodeBytes, err := rlp.EncodeToBytes(decIndex)
	assert.NoError(t, err)

	//fmt.Println("rlp encode data", "data", hexutil.Encode(encodeBytes))
	//fmt.Println("rlp decode data", "data", hexutil.Encode(decodeBytes))
	assert.Equal(t, encodeBytes, decodeBytes)
}

func TestWithRecord(t *testing.T) {
	r := NewWithdrawRecord()
	r2 := r.DeepCopy()
	r2.TxHash = common.StringToHash("abc")
	assert.NotEqual(t, r.TxHash, r2.TxHash)
}
