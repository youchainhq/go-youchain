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

package staking

import (
	"encoding/json"
	"fmt"
	"github.com/youchainhq/go-youchain/common/math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
)

var (
	testKey, _   = crypto.GenerateKey()
	testPubBytes = crypto.CompressPubkey(&testKey.PublicKey)
	testMaster   = crypto.PubkeyToAddress(testKey.PublicKey)
)

func TestCreateValidator(t *testing.T) {
	addr := common.BigToAddress(big.NewInt(1))
	msg := &TxCreateValidator{
		Name:            "abcabc",
		OperatorAddress: addr,
		Coinbase:        addr,
		BlsPubKey:       testPubBytes,
		MainPubKey:      testPubBytes,
		Value:           big.NewInt(1000),
		Role:            params.RoleChancellor,
		Nonce:           100,
	}
	msg.Coinbase = common.Address{}
	err := msg.PreCheck()
	assert.Error(t, err)
	msg.Coinbase = addr
	err = msg.PreCheck()
	assert.NoError(t, err)
	payload, err := rlp.EncodeToBytes(msg)
	assert.NoError(t, err)
	sign, err := MakeSign(msg, testKey)
	assert.NoError(t, err)
	msg.Sign = sign
	assert.True(t, msg.Verify(100, testMaster))

	msg2 := &TxCreateValidator{}
	err = rlp.DecodeBytes([]byte(payload), &msg2)
	assert.NoError(t, err)

	assert.Equal(t, msg.Value, msg2.Value)
	assert.Equal(t, msg.Nonce, msg2.Nonce)
	assert.Equal(t, msg.Hash(), msg2.Hash())
	assert.Equal(t, msg.Role, msg2.Role)
	assert.False(t, msg2.Verify(100, common.Address{}))

	js2, _ := json.Marshal(msg2)
	fmt.Println(string(js2))

	testEncodeMessage(t, ValidatorCreate, msg)
}

func testEncodeMessage(t *testing.T, action ActionType, msg Msg) {
	data, err := EncodeMessage(action, msg)
	assert.NoError(t, err)
	var message Message
	err = rlp.DecodeBytes(data, &message)
	assert.NoError(t, err)
}

func TestUpdateValidator(t *testing.T) {
	addr := common.BigToAddress(big.NewInt(1))
	msg := &TxUpdateValidator{
		Nonce:            100,
		Name:             "you node",
		MainAddress:      addr,
		OperatorAddress:  addr,
		Coinbase:         addr,
		CommissionRate:   1000,
		RiskObligation:   math.MaxUint16,
		AcceptDelegation: math.MaxUint16,
	}
	err := msg.PreCheck()
	assert.NoError(t, err)
	payload, err := rlp.EncodeToBytes(msg)
	fmt.Println("msg", hexutil.Encode(payload))
	assert.NoError(t, err)
	sign, err := MakeSign(msg, testKey)
	assert.NoError(t, err)
	msg.Sign = sign
	assert.True(t, msg.Verify(100, testMaster))

	msg2 := TxUpdateValidator{}
	err = rlp.DecodeBytes([]byte(payload), &msg2)
	assert.NoError(t, err)

	assert.Equal(t, msg.Coinbase, msg2.Coinbase)
	assert.Equal(t, msg.Nonce, msg2.Nonce)
	assert.Equal(t, msg.Hash(), msg2.Hash())
	assert.False(t, msg2.Verify(100, common.Address{}))

	js2, _ := json.Marshal(msg2)
	fmt.Println(string(js2))
	payload, err = rlp.EncodeToBytes(msg2)
	fmt.Println("msg2", hexutil.Encode(payload))

	testEncodeMessage(t, ValidatorUpdate, msg)
}

func TestTxValidatorDeposit(t *testing.T) {
	msg := &TxValidatorDeposit{
		MainAddress: common.BigToAddress(big.NewInt(100)),
		Value:       big.NewInt(111111),
		Nonce:       1000000,
	}
	err := msg.PreCheck()
	assert.NoError(t, err)
	payload, err := rlp.EncodeToBytes(msg)
	fmt.Println("msg", hexutil.Encode(payload))
	assert.NoError(t, err)
	sign, err := MakeSign(msg, testKey)
	assert.NoError(t, err)
	msg.Sign = sign
	assert.True(t, msg.Verify(1000000, testMaster))

	msg2 := TxValidatorDeposit{}
	err = rlp.DecodeBytes([]byte(payload), &msg2)
	assert.NoError(t, err)

	assert.Equal(t, msg.Value, msg2.Value)
	assert.Equal(t, msg.Nonce, msg2.Nonce)
	assert.Equal(t, msg.Hash(), msg2.Hash())
	assert.False(t, msg2.Verify(1000000, common.Address{}))

	js2, _ := json.Marshal(msg2)
	fmt.Println(string(js2))
	payload, err = rlp.EncodeToBytes(msg2)
	fmt.Println("msg2", hexutil.Encode(payload))

	testEncodeMessage(t, ValidatorDeposit, msg)
}

func TestTxValidatorWithdraw(t *testing.T) {
	msg := &TxValidatorWithdraw{
		MainAddress: common.BigToAddress(big.NewInt(100)),
		Recipient:   common.BigToAddress(big.NewInt(1000)),
		Value:       big.NewInt(100),
		Nonce:       100000,
	}
	err := msg.PreCheck()
	assert.NoError(t, err)
	payload, err := rlp.EncodeToBytes(msg)
	fmt.Println("msg", hexutil.Encode(payload))
	assert.NoError(t, err)
	sign, err := MakeSign(msg, testKey)
	assert.NoError(t, err)
	msg.Sign = sign
	assert.True(t, msg.Verify(100000, testMaster))

	msg2 := TxValidatorWithdraw{}
	err = rlp.DecodeBytes([]byte(payload), &msg2)
	assert.NoError(t, err)

	js2, _ := json.Marshal(msg2)
	fmt.Println(string(js2))

	payload, err = rlp.EncodeToBytes(msg2)
	assert.NoError(t, err)
	fmt.Println("msg2", hexutil.Encode(payload))

	testEncodeMessage(t, ValidatorWithDraw, msg)
}

func TestTxValidatorChangeStatus(t *testing.T) {
	msg := &TxValidatorChangeStatus{
		MainAddress: common.BigToAddress(big.NewInt(100)),
		Status:      params.ValidatorOnline,
		Nonce:       100000,
	}
	err := msg.PreCheck()
	assert.NoError(t, err)
	payload, err := rlp.EncodeToBytes(msg)
	fmt.Println("msg", hexutil.Encode(payload))
	assert.NoError(t, err)
	sign, err := MakeSign(msg, testKey)
	assert.NoError(t, err)
	msg.Sign = sign
	assert.True(t, msg.Verify(100000, testMaster))

	msg2 := TxValidatorChangeStatus{}
	err = rlp.DecodeBytes([]byte(payload), &msg2)
	assert.NoError(t, err)

	assert.Equal(t, msg.Status, msg2.Status)
	assert.Equal(t, msg.Nonce, msg2.Nonce)
	assert.Equal(t, msg.Hash(), msg2.Hash())
	assert.False(t, msg2.Verify(100000, common.Address{}))

	js2, _ := json.Marshal(msg2)
	fmt.Println(string(js2))

	testEncodeMessage(t, ValidatorChangeStatus, msg)
}

func TestTxValidatorSettle(t *testing.T) {
	tx := &TxValidatorSettle{
		MainAddress: common.BigToAddress(big.NewInt(100)),
	}
	bs, err := rlp.EncodeToBytes(tx)
	assert.NoError(t, err)
	fmt.Println("bs", hexutil.Encode(bs))

	var tx2 TxValidatorSettle
	err = rlp.DecodeBytes(bs, &tx2)
	assert.NoError(t, err)
	assert.Equal(t, tx.MainAddress, tx2.MainAddress)
	bs2, err := rlp.EncodeToBytes(tx2)
	assert.NoError(t, err)
	fmt.Println("bs2", hexutil.Encode(bs2))

	testEncodeMessage(t, ValidatorSettle, tx)
}
