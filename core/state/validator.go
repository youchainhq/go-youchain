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
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"io"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
)

type Extension struct {
	Version uint8         `json:"version"`
	Data    hexutil.Bytes `json:"data"`
}

type Validator struct {
	Name            string               `json:"name"`            // alias name for validator
	OperatorAddress common.Address       `json:"operatorAddress"` // manager address
	Coinbase        common.Address       `json:"coinbase"`        // send rewards
	Role            params.ValidatorRole `json:"role"`            // role of validator
	Status          uint8                `json:"status"`
	Expelled        bool                 `json:"expelled" rlp:"-"` // rlp did not support bool type
	ExpelExpired    uint64               `json:"expelExpired"`
	LastInactive    uint64               `json:"lastInactive"`

	MainPubKey hexutil.Bytes `json:"mainPubKey"` // consensus pubkey
	BlsPubKey  hexutil.Bytes `json:"blsPubKey"`  // bls pubkey

	Token     *big.Int `json:"token"`     // Lu
	Stake     *big.Int `json:"stake"`     // token / StakeUnit
	SelfToken *big.Int `json:"selfToken"` // self staking tokens, LU
	SelfStake *big.Int `json:"selfStake"`

	RewardsDistributable *big.Int `json:"rewardsDistributable"`
	RewardsTotal         *big.Int `json:"rewardsTotal"`
	RewardsLastSettled   uint64   `json:"rewardsLastSettled"`

	AcceptDelegation uint16          `json:"acceptDelegation"`
	CommissionRate   uint16          `json:"commissionRate"` // 抽佣率，万分数
	RiskObligation   uint16          `json:"riskObligation"` // 风险承担率，万分数
	Delegations      DelegationFroms `json:"delegations"`    // 名下委托集合，必须是排好序的

	// for later extend
	Ext Extension `json:"ext"`

	deleted bool

	// caches
	consAddr atomic.Value
}

// NewValidator creates a validator object.
func NewValidator(name string, operatorAddress, coinbase common.Address, role params.ValidatorRole, mainPubKey, blsPubKey hexutil.Bytes, token, stake *big.Int, acceptDelegation, commissionRate, riskObligation uint16, status uint8) *Validator {
	return &Validator{
		Name:                 name,
		OperatorAddress:      operatorAddress,
		Coinbase:             coinbase,
		Role:                 role,
		Status:               status,
		MainPubKey:           mainPubKey,
		BlsPubKey:            blsPubKey,
		Token:                new(big.Int).Set(token),
		Stake:                new(big.Int).Set(stake),
		SelfToken:            new(big.Int).Set(token),
		SelfStake:            new(big.Int).Set(stake),
		RewardsDistributable: big.NewInt(0),
		RewardsTotal:         big.NewInt(0),
		AcceptDelegation:     acceptDelegation,
		CommissionRate:       commissionRate,
		RiskObligation:       riskObligation,
		Delegations:          make(DelegationFroms, 0),
	}
}

type AliasValidator Validator // alias to Validator, for the purpose of marshalling or encoding.
type validatorJSON struct {
	AliasValidator
	MainAddress common.Address `json:"mainAddress"`
}

func (v Validator) MarshalJSON() ([]byte, error) {
	return json.Marshal(&validatorJSON{
		AliasValidator: AliasValidator(v),
		MainAddress:    v.MainAddress(),
	})
}

func (v Validator) Kind() params.ValidatorKind {
	kind, _ := params.KindOfRole(v.Role)
	return kind
}

func (v *Validator) IsOperator(addr common.Address) bool {
	return addr == v.OperatorAddress && addr != (common.Address{})
}

func (v Validator) StakeEqual(val *Validator) bool {
	if val == nil {
		return false
	}
	if v.Role == val.Role && v.Stake.Cmp(val.Stake) == 0 && v.Token.Cmp(val.Token) == 0 && v.Status == val.Status {
		return true
	}
	return false
}

func (v Validator) Equal(val *Validator) bool {
	if v.OperatorAddress != val.OperatorAddress {
		return false
	}
	if v.Coinbase != val.Coinbase {
		return false
	}
	if v.Role != val.Role {
		return false
	}
	if !bytes.Equal(v.MainPubKey, val.MainPubKey) {
		return false
	}
	if !bytes.Equal(v.BlsPubKey, val.BlsPubKey) {
		return false
	}
	if v.Token.Cmp(val.Token) != 0 {
		return false
	}
	if v.Stake.Cmp(val.Stake) != 0 {
		return false
	}
	if v.Status != val.Status {
		return false
	}
	return true
}

func (v *Validator) DeepCopy() *Validator {
	newVal := v.PartialCopy()
	if v.Delegations.Len() > 0 {
		newVal.Delegations = make(DelegationFroms, v.Delegations.Len())
		for i, value := range v.Delegations {
			newVal.Delegations[i] = value.DeepCopy()
		}
	}
	return newVal
}

// PartialCopy is a deep copy except that PartialCopy do not copy the Delegations slice
func (v *Validator) PartialCopy() *Validator {
	newVal := NewValidator(v.Name, v.OperatorAddress, v.Coinbase, v.Role, v.MainPubKey, v.BlsPubKey, v.SelfToken, v.SelfStake, v.AcceptDelegation, v.CommissionRate, v.RiskObligation, v.Status)
	newVal.Token.Set(v.Token)
	newVal.Stake.Set(v.Stake)
	newVal.RewardsDistributable.Set(v.RewardsDistributable)
	newVal.RewardsTotal.Set(v.RewardsTotal)
	newVal.RewardsLastSettled = v.RewardsLastSettled
	newVal.Expelled = v.Expelled
	newVal.ExpelExpired = v.ExpelExpired
	newVal.LastInactive = v.LastInactive
	newVal.deleted = v.deleted
	if consAddr := v.consAddr.Load(); consAddr != nil {
		newVal.consAddr.Store(consAddr)
	}
	newVal.Delegations = v.Delegations
	return newVal
}

func (v *Validator) MainAddress() common.Address {
	if hash := v.consAddr.Load(); hash != nil {
		return hash.(common.Address)
	}
	addr := PubToAddress(v.MainPubKey)
	v.consAddr.Store(addr)
	return addr
}

func PubToAddress(pubkey []byte) common.Address {
	var (
		pk  *ecdsa.PublicKey
		err error
	)
	if len(pubkey) == 33 {
		pk, err = crypto.DecompressPubkey(pubkey)
	} else if len(pubkey) == 65 {
		pk, err = crypto.UnmarshalPubkey(pubkey)
	} else {
		return common.Address{}
	}
	if err != nil {
		logging.Error("get sign addr failed", "err", err)
		return common.Address{}
	}
	addr := crypto.PubkeyToAddress(*pk)
	return addr
}

func (v *Validator) IsInvalid() bool {
	return v.Token.Uint64() <= 0 && v.Stake.Uint64() <= 0
}

func (v *Validator) IsOnline() bool {
	return v.Status == params.ValidatorOnline
}

func (v *Validator) IsOffline() bool {
	return v.Status != params.ValidatorOnline
}

func (v *Validator) Less(val *Validator) bool {
	iStake := v.Stake.Uint64()
	jStake := val.Stake.Uint64()
	if iStake == jStake {
		cmp := v.Token.Cmp(val.Token)
		if cmp == 0 {
			return bytes.Compare(v.MainAddress().Bytes(), val.MainAddress().Bytes()) < 0
		}
		return cmp < 0
	}
	return iStake < jStake
}

func (v *Validator) GetDelegationFrom(d common.Address) *DelegationFrom {
	i := v.Delegations.Search(d)
	if i < v.Delegations.Len() && v.Delegations[i].Delegator == d {
		return v.Delegations[i].DeepCopy()
	}
	return nil
}

func (v *Validator) UpdateDelegationFrom(d *DelegationFrom) (flag params.CurdFlag) {
	empty := d.Empty()
	i := v.Delegations.Search(d.Delegator)
	oldLen := v.Delegations.Len()
	if i == oldLen || v.Delegations[i].Delegator != d.Delegator {
		// not exist
		if empty {
			return params.Noop
		}
		//add new
		v.Delegations = append(v.Delegations, d)
		if i < oldLen {
			copy(v.Delegations[i+1:], v.Delegations[i:oldLen])
			v.Delegations[i] = d
		}
		return params.Create
	} else {
		// already exist
		if empty {
			// delete
			copy(v.Delegations[i:oldLen-1], v.Delegations[i+1:])
			v.Delegations[oldLen-1] = nil
			v.Delegations = v.Delegations[:oldLen-1]
			return params.Delete
		}
		//update directly
		v.Delegations[i] = d
		return params.Update
	}
}

func (v *Validator) AddTotalRewards(reward *big.Int) {
	v.RewardsDistributable.Add(v.RewardsDistributable, reward)
	v.RewardsTotal.Add(v.RewardsTotal, reward)
}

type rlpVal struct {
	AliasValidator
	Expelled uint8
}

func (v Validator) EncodeRLP(w io.Writer) error {
	if v.Token == nil {
		v.Token = big.NewInt(0)
	}
	if v.Stake == nil {
		v.Stake = big.NewInt(0)
	}
	if v.RewardsDistributable == nil {
		v.RewardsDistributable = new(big.Int)
	}
	if v.RewardsTotal == nil {
		v.RewardsTotal = new(big.Int)
	}
	if v.SelfToken == nil {
		v.SelfToken = new(big.Int)
	}
	if v.SelfStake == nil {
		v.SelfStake = new(big.Int)
	}
	expelled := uint8(0)
	if v.Expelled {
		expelled = 1
	}
	rv := &rlpVal{
		AliasValidator: AliasValidator(v),
		Expelled:       expelled,
	}
	return rlp.Encode(w, rv)
}

func (v *Validator) DecodeRLP(s *rlp.Stream) error {
	var r rlpVal
	if err := s.Decode(&r); err != nil {
		return err
	}

	v.Name = r.Name
	v.OperatorAddress = r.OperatorAddress
	v.Coinbase = r.Coinbase
	v.ExpelExpired = r.ExpelExpired
	v.LastInactive = r.LastInactive
	v.RewardsLastSettled = r.RewardsLastSettled
	v.CommissionRate = r.CommissionRate
	v.RiskObligation = r.RiskObligation
	v.AcceptDelegation = r.AcceptDelegation
	v.Role = params.ValidatorRole(r.Role)
	v.Status = r.Status
	v.MainPubKey = r.MainPubKey
	v.BlsPubKey = r.BlsPubKey
	v.Token = r.Token
	v.Stake = r.Stake
	v.SelfToken = r.SelfToken
	v.SelfStake = r.SelfStake
	v.RewardsDistributable = r.RewardsDistributable
	v.RewardsTotal = r.RewardsTotal
	v.Delegations = r.Delegations
	v.Ext = r.Ext

	if r.Expelled == 1 {
		v.Expelled = true
	}
	return nil
}

func (v Validator) Dump() DumpValidator {
	d := DumpValidator{
		MainAddress:          v.MainAddress(),
		Name:                 v.Name,
		OperatorAddress:      v.OperatorAddress,
		Coinbase:             v.Coinbase,
		MainPubKey:           v.MainPubKey,
		BlsPubKey:            v.BlsPubKey,
		Token:                v.Token.String(),
		Stake:                v.Stake.String(),
		Status:               v.Status,
		Role:                 uint8(v.Role),
		Expelled:             v.Expelled,
		ExpelExpired:         v.ExpelExpired,
		LastInactive:         v.LastInactive,
		SelfToken:            v.SelfToken.String(),
		SelfStake:            v.SelfStake.String(),
		RewardsDistributable: v.RewardsDistributable.String(),
		RewardsTotal:         v.RewardsTotal.String(),
		RewardsLastSettled:   v.RewardsLastSettled,
		AcceptDelegation:     v.AcceptDelegation,
		CommissionRate:       v.CommissionRate,
		RiskObligation:       v.RiskObligation,
		Ext:                  v.Ext,
	}
	d.Delegations = make([]*DumpDelegationFrom, len(v.Delegations))
	for i, df := range v.Delegations {
		d.Delegations[i] = &DumpDelegationFrom{
			Delegator: df.Delegator,
			Stake:     df.Stake.String(),
			Token:     df.Token.String(),
		}
	}
	return d
}

type ValKindStat struct {
	onlineStake *big.Int // online total token
	onlineToken *big.Int // online total token
	onlineCount uint64   // online validators count

	offlineStake *big.Int
	offlineToken *big.Int
	offlineCount uint64

	rewardsResidue       *big.Int
	rewardsDistributable *big.Int
}

func NewValKindStat() *ValKindStat {
	return &ValKindStat{
		onlineStake: new(big.Int),
		onlineToken: new(big.Int),
		onlineCount: 0,

		offlineStake: new(big.Int),
		offlineToken: new(big.Int),
		offlineCount: 0,

		rewardsDistributable: new(big.Int),
		rewardsResidue:       new(big.Int),
	}
}

func (v ValKindStat) Dump() DumpValidatorsStatItem {
	return DumpValidatorsStatItem{
		OnlineStake:          v.GetOnlineStake().String(),
		OnlineToken:          v.GetOnlineToken().String(),
		OnlineCount:          v.GetCount(),
		OfflineStake:         v.GetOfflineStake().String(),
		OfflineToken:         v.GetOfflineToken().String(),
		OfflineCount:         v.GetOfflineCount(),
		RewardsResidue:       v.GetRewardsResidue().String(),
		RewardsDistributable: v.GetRewardsDistributable().String(),
	}
}

func (v ValKindStat) GetOnlineStake() *big.Int {
	return new(big.Int).Set(v.onlineStake)
}
func (v ValKindStat) GetOnlineToken() *big.Int {
	return new(big.Int).Set(v.onlineToken)
}
func (v ValKindStat) GetOfflineStake() *big.Int {
	return new(big.Int).Set(v.offlineStake)
}
func (v ValKindStat) GetOfflineToken() *big.Int {
	return new(big.Int).Set(v.offlineToken)
}
func (v ValKindStat) GetRewardsDistributable() *big.Int {
	return new(big.Int).Set(v.rewardsDistributable)
}
func (v ValKindStat) GetRewardsResidue() *big.Int {
	return new(big.Int).Set(v.rewardsResidue)
}
func (v ValKindStat) GetCount() uint64 {
	return v.onlineCount
}
func (v ValKindStat) GetOfflineCount() uint64 {
	return v.offlineCount
}

func (v *ValKindStat) SubVal(val *Validator) {
	if val.Status == params.ValidatorOnline {
		v.subStake(val.Stake).subToken(val.Token).subCount(1)
	} else {
		v.subOfflineStake(val.Stake).subOfflineToken(val.Token).subOfflineCount(1)
	}
}
func (v *ValKindStat) AddVal(val *Validator) {
	if val.Status == params.ValidatorOnline {
		v.addStake(val.Stake).addToken(val.Token).addCount(1)
	} else {
		v.addOfflineStake(val.Stake).addOfflineToken(val.Token).addOfflineCount(1)
	}
}

func (v *ValKindStat) addStake(stake *big.Int) *ValKindStat {
	v.onlineStake.Add(v.onlineStake, stake)
	return v
}

func (v *ValKindStat) subStake(stake *big.Int) *ValKindStat {
	if v.onlineStake.Cmp(stake) >= 0 {
		v.onlineStake.Sub(v.onlineStake, stake)
	}
	return v
}

func (v *ValKindStat) addOfflineStake(stake *big.Int) *ValKindStat {
	v.offlineStake.Add(v.offlineStake, stake)
	return v
}

func (v *ValKindStat) subOfflineStake(stake *big.Int) *ValKindStat {
	if v.offlineStake.Cmp(stake) >= 0 {
		v.offlineStake.Sub(v.offlineStake, stake)
	}
	return v
}

func (v *ValKindStat) addToken(token *big.Int) *ValKindStat {
	v.onlineToken.Add(v.onlineToken, token)
	return v
}
func (v *ValKindStat) subToken(token *big.Int) *ValKindStat {
	if v.onlineToken.Cmp(token) >= 0 {
		v.onlineToken.Sub(v.onlineToken, token)
	}
	return v
}

func (v *ValKindStat) addOfflineToken(token *big.Int) *ValKindStat {
	v.offlineToken.Add(v.offlineToken, token)
	return v
}

func (v *ValKindStat) subOfflineToken(token *big.Int) *ValKindStat {
	if v.offlineToken.Cmp(token) >= 0 {
		v.offlineToken.Sub(v.offlineToken, token)
	}
	return v
}

func (v *ValKindStat) addCount(num uint64) *ValKindStat {
	v.onlineCount += num
	return v
}

func (v *ValKindStat) subCount(num uint64) *ValKindStat {
	v.onlineCount -= num
	return v
}

func (v *ValKindStat) addOfflineCount(num uint64) *ValKindStat {
	v.offlineCount += num
	return v
}

func (v *ValKindStat) subOfflineCount(num uint64) *ValKindStat {
	v.offlineCount -= num
	return v
}

func (v *ValKindStat) SetRewardsResidue(amount *big.Int) *ValKindStat {
	v.rewardsResidue.Set(amount)
	return v
}

func (v *ValKindStat) AddRewards(amount *big.Int) *ValKindStat {
	v.rewardsDistributable.Add(v.rewardsDistributable, amount)
	return v
}

func (v *ValKindStat) ResetRewards(total *big.Int) *ValKindStat {
	v.rewardsDistributable.Set(total)
	return v
}

func (v ValKindStat) DeepCopy() *ValKindStat {
	return &ValKindStat{
		onlineStake:          v.GetOnlineStake(),
		onlineToken:          v.GetOnlineToken(),
		onlineCount:          v.onlineCount,
		offlineStake:         v.GetOfflineStake(),
		offlineToken:         v.GetOfflineToken(),
		offlineCount:         v.offlineCount,
		rewardsResidue:       v.GetRewardsResidue(),
		rewardsDistributable: v.GetRewardsDistributable(),
	}
}

func (v ValKindStat) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{
		v.onlineStake,
		v.onlineToken,
		v.onlineCount,
		v.offlineStake,
		v.offlineToken,
		v.offlineCount,
		v.rewardsResidue,
		v.rewardsDistributable,
	})
}

func (v *ValKindStat) DecodeRLP(s *rlp.Stream) error {
	var data struct {
		Stake          *big.Int
		Token          *big.Int
		Count          uint64
		OfflineStake   *big.Int
		OfflineToken   *big.Int
		OfflineCount   uint64
		RewardsResidue *big.Int
		Rewards        *big.Int
	}

	if err := s.Decode(&data); err != nil {
		return err
	}

	v.onlineStake = data.Stake
	v.onlineToken = data.Token
	v.onlineCount = data.Count
	v.offlineStake = data.OfflineStake
	v.offlineToken = data.OfflineToken
	v.offlineCount = data.OfflineCount
	v.rewardsResidue = data.RewardsResidue
	v.rewardsDistributable = data.Rewards
	return nil
}

type ValidatorsStat struct {
	Kinds map[params.ValidatorKind]*ValKindStat `json:"kinds"`
	Roles map[params.ValidatorRole]*ValKindStat `json:"roles"`
}

func NewValidatorsStat() *ValidatorsStat {
	return &ValidatorsStat{
		Kinds: map[params.ValidatorKind]*ValKindStat{
			params.KindValidator: NewValKindStat(),
			params.KindChamber:   NewValKindStat(),
			params.KindHouse:     NewValKindStat(),
		},
		Roles: map[params.ValidatorRole]*ValKindStat{
			params.RoleChancellor: NewValKindStat(),
			params.RoleSenator:    NewValKindStat(),
			params.RoleHouse:      NewValKindStat(),
		},
	}
}

func (m *ValidatorsStat) GetByKind(kind params.ValidatorKind) *ValKindStat {
	return m.Kinds[kind]
}

func (m *ValidatorsStat) GetStakeByKind(kind params.ValidatorKind) *big.Int {
	return m.GetByKind(kind).GetOnlineStake()
}

func (m *ValidatorsStat) GetCountOfKind(kind params.ValidatorKind) uint64 {
	return m.GetByKind(kind).GetCount()
}

func (m *ValidatorsStat) GetRewardResidue() *big.Int {
	return m.GetByKind(params.KindValidator).GetRewardsResidue()
}

func (m *ValidatorsStat) GetByRole(role params.ValidatorRole) *ValKindStat {
	return m.Roles[role]
}

func (m *ValidatorsStat) String() string {
	bs, _ := json.Marshal(m)
	return string(bs)
}

func (m *ValidatorsStat) DeepCopy() *ValidatorsStat {
	stat := NewValidatorsStat()
	for _, kind := range []params.ValidatorKind{params.KindValidator, params.KindChamber, params.KindHouse} {
		stat.Kinds[kind] = m.Kinds[kind].DeepCopy()
	}
	for _, role := range []params.ValidatorRole{params.RoleChancellor, params.RoleSenator, params.RoleHouse} {
		stat.Roles[role] = m.Roles[role].DeepCopy()
	}
	return stat
}

func (m *ValidatorsStat) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{
		m.Kinds[params.KindValidator],
		m.Kinds[params.KindChamber],
		m.Kinds[params.KindHouse],
		m.Roles[params.RoleChancellor],
		m.Roles[params.RoleSenator],
		m.Roles[params.RoleHouse],
	})
}

func (m *ValidatorsStat) DecodeRLP(s *rlp.Stream) error {
	var data struct {
		KindValidator  *ValKindStat
		KindChamber    *ValKindStat
		KindHouse      *ValKindStat
		RoleChancellor *ValKindStat
		RoleSenator    *ValKindStat
		RoleHouse      *ValKindStat
	}
	if err := s.Decode(&data); err != nil {
		return err
	}

	m.Kinds[params.KindValidator] = data.KindValidator
	m.Kinds[params.KindChamber] = data.KindChamber
	m.Kinds[params.KindHouse] = data.KindHouse

	m.Roles[params.RoleChancellor] = data.RoleChancellor
	m.Roles[params.RoleSenator] = data.RoleSenator
	m.Roles[params.RoleHouse] = data.RoleHouse
	return nil
}

func (m ValidatorsStat) Dump() *DumpValidatorsStat {
	dump := &DumpValidatorsStat{
		Kinds: make(map[params.ValidatorKind]DumpValidatorsStatItem),
		Roles: make(map[params.ValidatorRole]DumpValidatorsStatItem),
	}
	for _, kind := range []params.ValidatorKind{params.KindValidator, params.KindChamber, params.KindHouse} {
		item := m.GetByKind(kind)
		dump.Kinds[kind] = item.Dump()
	}
	for _, role := range []params.ValidatorRole{params.RoleChancellor, params.RoleSenator, params.RoleHouse} {
		item := m.GetByRole(role)
		dump.Roles[role] = item.Dump()
	}
	return dump
}

type Validators struct {
	validators []*Validator
	index      map[common.Address]int // order by stake
}

func NewValidators(list []*Validator) *Validators {
	vs := &Validators{
		validators: make([]*Validator, len(list)),
		index:      make(map[common.Address]int, len(list)),
	}

	if list != nil && len(list) > 0 {
		for i, v := range list {
			vs.validators[i] = v
		}
		vs.sort()
	}
	return vs
}

func (s *Validators) sort() {
	sort.Sort(sort.Reverse(s))
	for idx, val := range s.validators {
		s.index[val.MainAddress()] = idx
	}
}

func (s Validators) List() []*Validator {
	return s.validators
}

func (s Validators) GetByIndex(index int) (*Validator, bool) {
	if index < 0 || index >= len(s.validators) {
		return nil, false
	}
	return s.validators[index], true
}

func (s Validators) GetIndex(mainAddress common.Address) (int, bool) {
	index, ok := s.index[mainAddress]
	return index, ok
}

func (s *Validators) Remove(mainAddress common.Address) bool {
	idx := -1
	var removedVal *Validator
	for i, val := range s.validators {
		if val.MainAddress() == mainAddress {
			idx = i
			removedVal = val
			break
		}
	}
	if idx < 0 || removedVal == nil {
		return false
	}
	s.validators = append(s.validators[:idx], s.validators[idx+1:]...)
	return true
}

func (s *Validators) Less(i, j int) bool {
	return s.validators[i].Less(s.validators[j])
}

func (s *Validators) Swap(i, j int) {
	s.validators[i], s.validators[j] = s.validators[j], s.validators[i]
}

func (s Validators) Len() int {
	return len(s.validators)
}

func (s Validators) GetRlp(i int) []byte {
	bs, err := rlp.EncodeToBytes(s.validators[i])
	if err != nil {
		panic(err)
	}
	return bs
}

func (s Validators) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{s.validators})
}

func (s *Validators) DecodeRLP(stream *rlp.Stream) error {
	var msg struct {
		ValSet []*Validator
	}
	if err := stream.Decode(&msg); err != nil {
		return err
	}

	s.validators = msg.ValSet
	return nil
}

type WithdrawRecord struct {
	Operator         common.Address `json:"operator"`
	Delegator        common.Address `json:"delegator"`
	Validator        common.Address `json:"validator"`
	Recipient        common.Address `json:"recipient"`
	Nonce            uint64         `json:"nonce"`
	CreationHeight   uint64         `json:"creationHeight"`   // height which the withdraw took place
	CompletionHeight uint64         `json:"completionHeight"` // height which the withdraw will complete
	InitialBalance   *big.Int       `json:"initialBalance"`   // tokens initially scheduled to receive at completion
	FinalBalance     *big.Int       `json:"finalBalance"`     // tokens to receive at completion 最后实际收到的token数量
	Finished         uint8          `json:"finished"`
	TxHash           common.Hash    `json:"txHash"`
}

func NewWithdrawRecord() *WithdrawRecord {
	return &WithdrawRecord{}
}

func (u *WithdrawRecord) DeepCopy() *WithdrawRecord {
	r := *u
	if u.InitialBalance != nil {
		r.InitialBalance = new(big.Int).Set(u.InitialBalance)
	}
	if u.FinalBalance != nil {
		r.FinalBalance = new(big.Int).Set(u.FinalBalance)
	}
	return &r
}

func (u *WithdrawRecord) Dump() *DumpWithdrawRecord {
	return &DumpWithdrawRecord{
		Delegator:        u.Delegator,
		Validator:        u.Validator,
		Operator:         u.Operator,
		Nonce:            u.Nonce,
		Recipient:        u.Recipient,
		CreationHeight:   u.CreationHeight,
		CompletionHeight: u.CompletionHeight,
		InitialBalance:   u.InitialBalance.String(),
		FinalBalance:     u.FinalBalance.String(),
		Finished:         u.Finished,
	}
}

func (u *WithdrawRecord) String() string {
	return fmt.Sprintf("opaddr=%s nonce=%d validator=%s toaddr=%s CreationHeight=%d CompletionHeight=%d InitialBalance=%d FinalBalance=%d finished=%v tx=%s",
		u.Operator.String(),
		u.Nonce,
		u.Validator,
		u.Recipient.String(),
		u.CreationHeight,
		u.CompletionHeight,
		u.InitialBalance,
		u.FinalBalance,
		u.Finished,
		u.TxHash.String(),
	)
}

func (u WithdrawRecord) IsMature(height uint64) bool {
	return u.CompletionHeight < height
}

var _ sort.Interface = &WithdrawQueue{}

type WithdrawQueue struct {
	Records []*WithdrawRecord
}

func NewWithdrawQueue() *WithdrawQueue {
	return &WithdrawQueue{
		Records: []*WithdrawRecord{},
	}
}

func (q WithdrawQueue) DeepCopy() *WithdrawQueue {
	queue := &WithdrawQueue{
		Records: make([]*WithdrawRecord, q.Len()),
	}
	for i, r := range q.Records {
		queue.Records[i] = r.DeepCopy()
	}
	return queue
}

func (q WithdrawQueue) Len() int {
	return len(q.Records)
}

func (q WithdrawQueue) Less(i, j int) bool {
	return q.Records[i].CompletionHeight < q.Records[j].CompletionHeight
}

func (q *WithdrawQueue) Swap(i, j int) {
	q.Records[i], q.Records[j] = q.Records[j], q.Records[i]
}

func (q *WithdrawQueue) Add(record *WithdrawRecord) {
	q.Records = append(q.Records, record)
}

func (q *WithdrawQueue) Delete(record *WithdrawRecord) {
	deleted := -1
	for i, r := range q.Records {
		if r.Operator == record.Operator && r.Nonce == record.Nonce {
			deleted = i
		}
	}
	q.Records = append(q.Records[:deleted], q.Records[deleted+1:]...)
}

// RemoveEntry - remove entry at index i to the withdrawing delegation
func (q *WithdrawQueue) RemoveRecords(idx []int) []*WithdrawRecord {
	removed := make([]*WithdrawRecord, len(idx))
	for i, index := range idx {
		removed[i] = q.Records[index]
		q.Records[index] = nil
	}

	data := q.Records[:0]
	for e := range q.Records {
		if q.Records[e] != nil {
			data = append(data, q.Records[e])
		}
	}
	q.Records = data
	return removed
}

type ValidatorIndex struct {
	data sync.Map
}

func NewValidatorIndex() *ValidatorIndex {
	return &ValidatorIndex{
		data: sync.Map{},
	}
}

func (index *ValidatorIndex) DeepCopy() *ValidatorIndex {
	v := NewValidatorIndex()
	index.data.Range(func(key, value interface{}) bool {
		v.Add(key.(common.Address))
		return true
	})
	return v
}

func (index *ValidatorIndex) Empty() bool {
	i := 0
	index.data.Range(func(key, value interface{}) bool {
		i += 1
		return false
	})
	return i > 0
}

func (index *ValidatorIndex) List() []common.Address {
	var list addressList
	index.data.Range(func(addr, value interface{}) bool {
		list = append(list, addr.(common.Address))
		return true
	})
	sort.Sort(list)
	return list
}

func (index *ValidatorIndex) Add(mainAddress common.Address) {
	index.data.Store(mainAddress, nil)
}

func (index *ValidatorIndex) Delete(mainAddress common.Address) {
	index.data.Delete(mainAddress)
}

func (index *ValidatorIndex) EncodeRLP(w io.Writer) error {
	data := addressList{}
	index.data.Range(func(addr, value interface{}) bool {
		data = append(data, addr.(common.Address))
		return true
	})
	sort.Sort(data)
	return rlp.Encode(w, data)
}

func (index *ValidatorIndex) DecodeRLP(s *rlp.Stream) error {
	var list addressList
	if err := s.Decode(&list); err != nil {
		return err
	}
	for _, addr := range list {
		index.data.Store(addr, nil)
	}
	return nil
}

type addressList []common.Address

var _ sort.Interface = &addressList{}

func (a addressList) Len() int {
	return len(a)
}

func (a addressList) Less(i, j int) bool {
	return bytes.Compare(a[i].Bytes(), a[j].Bytes()) < 0
}

func (a addressList) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
