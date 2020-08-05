/*
 * Copyright 2020 YOUCHAIN FOUNDATION LTD.
 * Copyright 2016 The go-ethereum Authors
 * This file is part of the go-ethereum library.
 *
 * The go-ethereum library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The go-ethereum library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
 */

package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/trie"
)

type DumpAccount struct {
	Balance           string            `json:"balance"`
	Nonce             uint64            `json:"nonce"`
	Root              string            `json:"root"`
	Storage           map[string]string `json:"storage"`
	DelegationBalance string            `json:"delegationBalance"`
	Delegations       []string          `json:"delegations,omitempty"`
}

type DumpDelegationFrom struct {
	Delegator common.Address `json:"delegator"`
	Stake     string         `json:"stake"`
	Token     string         `json:"token"`
}

type DumpValidator struct {
	MainAddress     common.Address `json:"mainAddress"`
	Name            string         `json:"name"`
	OperatorAddress common.Address `json:"operatorAddress"`
	Coinbase        common.Address `json:"coinbase"`
	MainPubKey      hexutil.Bytes  `json:"mainPubKey"`
	BlsPubKey       hexutil.Bytes  `json:"blsPubKey"`
	Token           string         `json:"token"`
	Stake           string         `json:"stake"`
	Status          uint8          `json:"status"`
	Role            uint8          `json:"role"`
	Expelled        bool           `json:"expelled"`
	ExpelExpired    uint64         `json:"expelExpired"`
	LastInactive    uint64         `json:"lastInactive"`
	SelfToken       string         `json:"selfToken"` // self staking tokens, LU
	SelfStake       string         `json:"selfStake"`

	RewardsDistributable string `json:"rewardsDistributable"`
	RewardsTotal         string `json:"rewardsTotal"`
	RewardsLastSettled   uint64 `json:"rewardsLastSettled"` // 最后一次分配的区块的高度

	AcceptDelegation uint16                `json:"acceptDelegation"`
	CommissionRate   uint16                `json:"commissionRate"` // 抽佣率，万分数
	RiskObligation   uint16                `json:"riskObligation"` // 风险承担率，万分数
	Delegations      []*DumpDelegationFrom `json:"delegations"`    // 名下委托集合，必须是排好序的

	// for later extend
	Ext Extension `json:"ext"`
}

type DumpWithdrawRecord struct {
	Operator         common.Address `json:"operator"`
	Delegator        common.Address `json:"delegator"`
	Validator        common.Address `json:"validator"`
	Recipient        common.Address `json:"recipient"`
	Nonce            uint64         `json:"nonce"`
	CreationHeight   uint64         `json:"creationHeight"`   // height which the withdrawing took place
	CompletionHeight uint64         `json:"completionHeight"` // height which the withdrawing will complete
	InitialBalance   string         `json:"initialBalance"`   // tokens initially scheduled to receive at completion
	FinalBalance     string         `json:"finalBalance"`     // tokens to receive at completion 最后实际收到的token数量
	Finished         uint8          `json:"finished"`
	TxHash           common.Hash    `json:"txHash"`
}

type DumpValidatorsStatItem struct {
	OnlineStake          string `json:"onlineStake"`
	OnlineToken          string `json:"onlineToken"`
	OnlineCount          uint64 `json:"onlineCount"`
	OfflineStake         string `json:"offlineStake"`
	OfflineToken         string `json:"offlineToken"`
	OfflineCount         uint64 `json:"offlineCount"`
	RewardsResidue       string `json:"rewardsResidue"`
	RewardsDistributable string `json:"rewardsDistributable"`
}

type DumpValidatorsStat struct {
	Kinds map[params.ValidatorKind]DumpValidatorsStatItem `json:"kinds"`
	Roles map[params.ValidatorRole]DumpValidatorsStatItem `json:"roles"`
}

type Dump struct {
	Root               string                   `json:"root"`
	ValRoot            string                   `json:"valRoot"`
	StakingRoot        string                   `json:"stakingRoot"`
	Accounts           map[string]DumpAccount   `json:"accounts"`
	Validators         map[string]DumpValidator `json:"validators"`
	ValidatorsStat     *DumpValidatorsStat      `json:"validatorsStat"`
	ValidatorsWithdraw []*DumpWithdrawRecord    `json:"validatorsWithdraw"`
}

func (st *StateDB) RawDump() Dump {
	logging.Warn("!!!!!!!!!!!!!!!!!!!!!!!!!CAUTIOUS_YOU_ARE_CALLING_DUMP_OF_STATEDB_IT_WILL_TAKES_LONG_TIME!!!!!!!!!!!!!!!!!!!!!!!!!")

	dump := Dump{
		Root:               fmt.Sprintf("%x", st.trie.Hash()),
		ValRoot:            fmt.Sprintf("%x", st.valTrie.Hash()),
		StakingRoot:        fmt.Sprintf("%x", st.stakingTrie.Hash()),
		Accounts:           make(map[string]DumpAccount),
		Validators:         make(map[string]DumpValidator),
		ValidatorsStat:     nil,
		ValidatorsWithdraw: []*DumpWithdrawRecord{},
	}

	vit := trie.NewIterator(st.valTrie.NodeIterator(nil))
	for vit.Next() {
		key := st.trie.GetKey(vit.Key)
		switch {
		case bytes.HasPrefix(key, validatorFlag):
			var val Validator
			if err := rlp.DecodeBytes(vit.Value[len(validatorFlag):], &val); err != nil {
				panic(err)
			}
			dump.Validators[val.MainAddress().String()] = val.Dump()

		case bytes.HasPrefix(key, validatorStatFlag):
			stat := NewValidatorsStat()
			if err := rlp.DecodeBytes(vit.Value[len(validatorStatFlag):], stat); err != nil {
				panic(err)
			}
			dump.ValidatorsStat = stat.Dump()

		case bytes.HasPrefix(key, validatorWithdrawQueueFlag):
			var queue WithdrawQueue
			if err := rlp.DecodeBytes(vit.Value[len(validatorWithdrawQueueFlag):], &queue); err != nil {
				panic(err)
			}
			dumpRecords := make([]*DumpWithdrawRecord, queue.Len())
			for i, r := range queue.Records {
				dumpRecords[i] = r.Dump()
			}
			dump.ValidatorsWithdraw = dumpRecords
		}
	}

	it := trie.NewIterator(st.trie.NodeIterator(nil))
	for it.Next() {
		addr := st.trie.GetKey(it.Key)
		var data Account
		if err := rlp.DecodeBytes(it.Value, &data); err != nil {
			panic(err)
		}

		obj := newObject(st, common.BytesToAddress(addr), data)
		account := DumpAccount{
			Balance:           data.Balance.String(),
			Nonce:             data.Nonce,
			Root:              common.Bytes2Hex(data.Root[:]),
			Storage:           make(map[string]string),
			DelegationBalance: data.DelegationBalance.String(),
		}
		for _, d := range obj.Delegations() {
			account.Delegations = append(account.Delegations, d.String())
		}
		storageIt := trie.NewIterator(obj.getTrie(st.db).NodeIterator(nil))
		for storageIt.Next() {
			_, content, _, err := rlp.Split(storageIt.Value)
			if err != nil {
				logging.Error("Failed to decode the value returned by iterator", "error", err)
				continue
			}
			account.Storage[common.Bytes2Hex(st.trie.GetKey(storageIt.Key))] = common.Bytes2Hex(content)
		}
		dump.Accounts[common.Bytes2Hex(addr)] = account
	}
	return dump
}

func (st *StateDB) Dump() []byte {
	content, err := json.MarshalIndent(st.RawDump(), "", "    ")
	if err != nil {
		fmt.Println("dump err", err)
	}

	return content
}

type DumpLog struct {
	Address     common.Address `json:"address"`
	Topics      []common.Hash  `json:"topics"`
	Data        hexutil.Bytes  `json:"data"`
	BlockNumber hexutil.Uint64 `json:"blockNumber"`
	TxHash      common.Hash    `json:"transactionHash"`
	TxIndex     hexutil.Uint   `json:"transactionIndex"`
	BlockHash   common.Hash    `json:"blockHash"`
	Index       hexutil.Uint   `json:"logIndex"`
	Removed     bool           `json:"removed"`
}

type DumpAllLogs struct {
	Logs map[string][]DumpLog `json:"txhash"`
}

func (st *StateDB) LogDump() (DumpAllLogs, error) {
	alllogs := st.logs
	var dump DumpAllLogs
	for tx, logs := range alllogs {
		var dumplogs []DumpLog
		for _, log := range logs {
			var onelog DumpLog
			temp, err := log.MarshalJSON()
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(temp, &onelog)
			if err != nil {
				panic(err)
			}
			dumplogs = append(dumplogs, onelog)
		}
		dump.Logs[tx.Hex()] = dumplogs

	}

	return dump, nil
}
