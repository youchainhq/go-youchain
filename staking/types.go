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
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/youchainhq/go-youchain/common/math"
	"math/big"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
)

type engine interface {
	CheckValidatorVotes(chain consensus.ChainReader, header *types.Header) (map[common.Address]bool, error)
}

// DelegateActionType is the type of delegate action
type ActionType uint8

// split actions to groups
const (
	ValidatorCreate ActionType = 0x1 + iota
	ValidatorUpdate
	ValidatorDeposit
	ValidatorWithDraw
	ValidatorChangeStatus
	ValidatorSettle
)

const (
	DelegationAdd    ActionType = 0x10 + iota // add delegation
	DelegationSub                             // subtract delegation
	DelegationSettle                          // settle delegation rewards
)

// Message is the base message of a staking transaction
type Message struct {
	Action  ActionType
	Payload []byte
}

// EncodeMessage will do a PreCheck for the detailed-action-message
// and then pack it up to a staking-common-message using rlp encode.
func EncodeMessage(action ActionType, payload Msg) ([]byte, error) {
	if err := payload.PreCheck(); err != nil {
		return nil, err
	}
	bs, err := rlp.EncodeToBytes(payload)
	if err != nil {
		return nil, err
	}
	msg := &Message{Action: action, Payload: bs}
	return rlp.EncodeToBytes(msg)
}

//Msg is a interface for detailed action message
type Msg interface {
	PreCheck() error
	Hash() common.Hash
	Verify(nonce uint64, master common.Address) bool
}

var (
	_ Msg = &TxCreateValidator{}
	_ Msg = &TxUpdateValidator{}
	_ Msg = &TxValidatorDeposit{}
	_ Msg = &TxValidatorWithdraw{}
	_ Msg = &TxValidatorChangeStatus{}
	_ Msg = &TxValidatorSettle{}
)

func verifyValidatorName(name string) error {
	if len(name) > valNameMaxLength {
		return fmt.Errorf("validator name shoule be 0-%d chars", valNameMaxLength)
	}
	return nil
}

func MakeSign(msg Msg, key *ecdsa.PrivateKey) ([]byte, error) {
	hash := msg.Hash()
	return crypto.Sign(hash.Bytes(), key)
}

// TxCreateValidator create a new validator
type TxCreateValidator struct {
	Name             string               `json:"name"`            // alias name for validator
	OperatorAddress  common.Address       `json:"operatorAddress"` // operator is the address who can manage the validator
	Coinbase         common.Address       `json:"coinbase"`        // coinbase is the address that mining rewards will be send to
	MainPubKey       hexutil.Bytes        `json:"mainPubKey"`
	BlsPubKey        hexutil.Bytes        `json:"blsPubKey"`
	Value            *big.Int             `json:"value"`
	Nonce            uint64               `json:"nonce"`
	CommissionRate   uint16               `json:"commissionRate"` // number over ten-thousandth
	RiskObligation   uint16               `json:"riskObligation"`
	AcceptDelegation uint16               `json:"acceptDelegation"`
	Role             params.ValidatorRole `json:"role"`
	Sign             hexutil.Bytes        `json:"sign"` //hash(m.Hash().Bytes())
}

func (m *TxCreateValidator) PreCheck() error {
	if err := verifyValidatorName(m.Name); err != nil {
		return err
	}
	if m.OperatorAddress == (common.Address{}) {
		return fmt.Errorf("operator address can not be empty")
	}
	if m.Coinbase == (common.Address{}) {
		return fmt.Errorf("coinbase can not be empty")
	}
	if !params.CheckRole(m.Role) {
		return fmt.Errorf("unknown role %d", m.Role)
	}
	if m.Value == nil || m.Value.Sign() <= 0 {
		return fmt.Errorf("invalid value")
	}
	if len(m.MainPubKey[:]) == 0 {
		return fmt.Errorf("main pub key is required")
	}
	if len(m.BlsPubKey[:]) == 0 {
		return fmt.Errorf("bls pub key is required")
	}
	if m.AcceptDelegation > params.AcceptDelegation {
		return fmt.Errorf("value of AcceptDelegation should be ether 0 (not accept) or 1 (accept)")
	}
	if m.CommissionRate > params.CommissionRateBase {
		return fmt.Errorf("commission rate too hight, iuput=%d", m.CommissionRate)
	}
	if m.RiskObligation > params.CommissionRateBase {
		return fmt.Errorf("RiskObligation too hight, iuput=%d", m.RiskObligation)
	}
	return nil
}

func (m *TxCreateValidator) Verify(nonce uint64, master common.Address) bool {
	if len(m.Sign) == 0 || m.Nonce != nonce {
		return false
	}
	hash := m.Hash()
	return checkSign(hash, m.Sign, master)
}

func (m *TxCreateValidator) Hash() common.Hash {
	bs := new(bytes.Buffer)
	bs.WriteString(m.Name)
	bs.Write(m.OperatorAddress.Bytes())
	bs.Write(m.Coinbase.Bytes())
	bs.Write(m.MainPubKey)
	bs.Write(m.BlsPubKey)
	bs.Write(m.Value.Bytes())
	bs.Write(hexutil.Uint64ToBytes(m.Nonce))
	bs.Write(hexutil.Uint16ToBytes(m.AcceptDelegation))
	bs.Write(hexutil.Uint16ToBytes(m.CommissionRate))
	bs.Write(hexutil.Uint16ToBytes(m.RiskObligation))
	bs.WriteByte(uint8(m.Role))
	return crypto.Keccak256Hash(bs.Bytes())
}

// TxUpdateValidator 修改validator的信息
type TxUpdateValidator struct {
	Nonce            uint64         `json:"nonce"`
	Name             string         `json:"name"`
	MainAddress      common.Address `json:"mainAddress"`
	OperatorAddress  common.Address `json:"operatorAddress"`
	Coinbase         common.Address `json:"coinbase"`
	CommissionRate   uint16         `json:"commissionRate"` // number over ten-thousandth
	RiskObligation   uint16         `json:"riskObligation"`
	AcceptDelegation uint16         `json:"acceptDelegation"`
	Sign             hexutil.Bytes  `json:"sign"` //  hash(m.Hash().Bytes())
}

func (m *TxUpdateValidator) PreCheck() error {
	if err := verifyValidatorName(m.Name); err != nil {
		return err
	}
	if m.isSet(m.AcceptDelegation) && m.AcceptDelegation > params.AcceptDelegation {
		return fmt.Errorf("value of AcceptDelegation should be ether 0 (not accept) or 1 (accept)")
	}
	if m.isSet(m.CommissionRate) && m.CommissionRate > params.CommissionRateBase {
		return fmt.Errorf("commission rate too hight, iuput=%d", m.CommissionRate)
	}
	if m.isSet(m.RiskObligation) && m.RiskObligation > params.CommissionRateBase {
		return fmt.Errorf("RiskObligation too hight, iuput=%d", m.RiskObligation)
	}
	return nil
}

func (m *TxUpdateValidator) Hash() common.Hash {
	bs := new(bytes.Buffer)
	bs.Write(m.MainAddress.Bytes())
	bs.WriteString(m.Name)
	bs.Write(m.OperatorAddress.Bytes())
	bs.Write(m.Coinbase.Bytes())
	bs.Write(hexutil.Uint64ToBytes(m.Nonce))
	bs.Write(hexutil.Uint16ToBytes(m.AcceptDelegation))
	bs.Write(hexutil.Uint16ToBytes(m.CommissionRate))
	bs.Write(hexutil.Uint16ToBytes(m.RiskObligation))
	return crypto.Keccak256Hash(bs.Bytes())
}

func (m *TxUpdateValidator) Verify(nonce uint64, master common.Address) bool {
	if len(m.Sign) == 0 || m.Nonce != nonce {
		return false
	}
	hash := m.Hash()
	return checkSign(hash, m.Sign, master)
}

func (m *TxUpdateValidator) isSet(v uint16) bool {
	return v != math.MaxUint16
}

// TxValidatorDeposit more deposit for validator
type TxValidatorDeposit struct {
	MainAddress common.Address `json:"mainAddress"`
	Value       *big.Int       `json:"value"`
	Nonce       uint64         `json:"nonce"`
	Sign        hexutil.Bytes  `json:"sign"` //  hash(m.Hash().Bytes())
}

func (m *TxValidatorDeposit) Hash() common.Hash {
	bs := new(bytes.Buffer)
	bs.Write(m.MainAddress.Bytes())
	bs.Write(hexutil.Uint64ToBytes(m.Nonce))
	bs.Write(m.Value.Bytes())
	return crypto.Keccak256Hash(bs.Bytes())
}

func (m *TxValidatorDeposit) Verify(nonce uint64, master common.Address) bool {
	if len(m.Sign) == 0 || m.Nonce != nonce {
		return false
	}
	hash := m.Hash()
	return checkSign(hash, m.Sign, master)
}

func (m *TxValidatorDeposit) PreCheck() error {
	if m.Value.Cmp(bigZero) <= 0 {
		return fmt.Errorf("value is too low, value=%s", m.Value.String())
	}
	return nil
}

// TxValidatorWithdraw .
type TxValidatorWithdraw struct {
	MainAddress common.Address `json:"mainAddress"`
	Recipient   common.Address `json:"recipient"` // tokens will be refunded to this account
	Value       *big.Int       `json:"value"`     // tokens that the validator wants to withdraw
	Nonce       uint64         `json:"nonce"`
	Sign        hexutil.Bytes  `json:"sign"` // hash(m.Hash().Bytes())
}

func (m *TxValidatorWithdraw) Hash() common.Hash {
	bs := new(bytes.Buffer)
	bs.Write(m.MainAddress.Bytes())
	bs.Write(m.Recipient[:])
	bs.Write(hexutil.Uint64ToBytes(m.Nonce))
	bs.Write(m.Value.Bytes())
	return crypto.Keccak256Hash(bs.Bytes())
}

func (m *TxValidatorWithdraw) Verify(nonce uint64, master common.Address) bool {
	if len(m.Sign) == 0 || m.Nonce != nonce {
		return false
	}
	hash := m.Hash()
	return checkSign(hash, m.Sign, master)
}

func (m *TxValidatorWithdraw) PreCheck() error {
	if m.Recipient == (common.Address{}) {
		return errRecipientRequired
	}

	if m.Value == nil || m.Value.Cmp(bigZero) <= 0 {
		return fmt.Errorf("value is too low, input value=%s", m.Value.String())
	}
	return nil
}

// TxValidatorChangeStatus .
type TxValidatorChangeStatus struct {
	MainAddress common.Address `json:"mainAddress"`
	Status      uint8          `json:"status"`
	Nonce       uint64         `json:"nonce"`
	Sign        hexutil.Bytes  `json:"sign"`
}

func (m *TxValidatorChangeStatus) Hash() common.Hash {
	bs := new(bytes.Buffer)
	bs.Write(m.MainAddress.Bytes())
	bs.Write([]byte{m.Status})
	bs.Write(hexutil.Uint64ToBytes(m.Nonce))
	return crypto.Keccak256Hash(bs.Bytes())
}

func (m *TxValidatorChangeStatus) PreCheck() error {
	if m.Status != params.ValidatorOffline && m.Status != params.ValidatorOnline {
		return fmt.Errorf("invalidate status, shoule be 0 or 1")
	}
	return nil
}

func (m *TxValidatorChangeStatus) Verify(nonce uint64, master common.Address) bool {
	if len(m.Sign) == 0 || m.Nonce != nonce {
		return false
	}
	hash := m.Hash()
	return checkSign(hash, m.Sign, master)
}

type TxValidatorSettle struct {
	MainAddress common.Address `json:"mainAddress"`
}

func (m *TxValidatorSettle) PreCheck() error {
	return nil
}

func (m *TxValidatorSettle) Hash() common.Hash {
	bs := new(bytes.Buffer)
	bs.Write(m.MainAddress.Bytes())
	return crypto.Keccak256Hash(bs.Bytes())
}

func (m *TxValidatorSettle) Verify(nonce uint64, master common.Address) bool {
	return true
}

func checkSign(hash common.Hash, sign []byte, master common.Address) bool {
	signerPubKey, err := crypto.SigToPub(hash.Bytes(), sign)
	if err != nil {
		return false
	}
	signer := crypto.PubkeyToAddress(*signerPubKey)
	if signer != master {
		return false
	}
	return true
}

// TxDelegation contains module specific detail data for a delegation transaction
type TxDelegation struct {
	Validator common.Address //validator main address
	Value     *big.Int       // the value to add or subtract
}

func (t *TxDelegation) PreCheck() error {
	if t.Validator == (common.Address{}) {
		return errors.New("validator address is needed")
	}
	if t.Value == nil || t.Value.Sign() <= 0 {
		return errors.New("a positive value is needed")
	}
	return nil
}

func (t *TxDelegation) Hash() common.Hash {
	panic("implement me")
}

func (t *TxDelegation) Verify(uint64, common.Address) bool {
	panic("implement me")
}

type TxDelegationSettle struct {
	Validator common.Address //validator main address
}

func (t *TxDelegationSettle) PreCheck() error {
	if t.Validator == (common.Address{}) {
		return errors.New("validator address is needed")
	}
	return nil
}

func (t *TxDelegationSettle) Hash() common.Hash {
	panic("implement me")
}

func (t *TxDelegationSettle) Verify(uint64, common.Address) bool {
	panic("implement me")
}
