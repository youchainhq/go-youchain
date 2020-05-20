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
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync/atomic"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/crypto/sha3"
	"github.com/youchainhq/go-youchain/rlp"
)

//LogData LogData
type LogData struct {
	Topic string   `json:"topic"`
	Tags  []string `json:"tags"`
	Data  []byte   `json:"data"`
}

func newLogData(topic string, tags []string, data interface{}) *LogData {
	bs, _ := rlp.EncodeToBytes(data)
	return &LogData{
		Topic: topic,
		Tags:  tags,
		Data:  bs,
	}
}

//DecodeRLP .
func (l *LogData) DecodeRLP(s *rlp.Stream) error {
	var msg struct {
		Topic string
		Tags  []string
		Data  hexutil.Bytes
	}

	if err := s.Decode(&msg); err != nil {
		return err
	}
	l.Topic = msg.Topic
	l.Data = msg.Data
	l.Tags = msg.Tags
	return nil
}

//EncodeRLP .
func (l LogData) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{
		l.Topic,
		l.Tags,
		hexutil.Bytes(l.Data),
	})
}

//UnmarshalJSON .
func (l *LogData) UnmarshalJSON(bs []byte) error {
	var data struct {
		Topic string        `json:"topic"`
		Tags  []string      `json:"tags"`
		Data  hexutil.Bytes `json:"data"`
	}
	if err := json.Unmarshal(bs, &data); err != nil {
		return nil
	}
	l.Topic = data.Topic
	l.Tags = data.Tags
	l.Data = data.Data
	return nil
}

//MarshalJSON .
func (l LogData) MarshalJSON() ([]byte, error) {
	var data struct {
		Topic string        `json:"topic"`
		Tags  []string      `json:"tags"`
		Data  hexutil.Bytes `json:"data"`
	}
	data.Tags = l.Tags
	data.Topic = l.Topic
	data.Data = l.Data
	return json.Marshal(data)
}

//EncodeToBytes .
func (l LogData) EncodeToBytes() []byte {
	bs, err := rlp.EncodeToBytes(l)
	if err != nil {
		fmt.Println("err", err)
	}
	return bs
}

//SlashWithdrawRecord save modified withdraw record
type SlashWithdrawRecord struct {
	Token  *big.Int              `json:"token"`
	Record *state.WithdrawRecord `json:"record"`
}

//SlashData .
type SlashData struct {
	Type        uint8                  `json:"type"`
	MainAddress common.Address         `json:"mainAddress"`
	Total       *big.Int               `json:"penaltyAmount"` // total
	Records     []*SlashWithdrawRecord `json:"records"`       // from withdraw records
	Evidence    interface{}            `json:"evidence"`      // confirmed evidence

	hash atomic.Value
}

//NewSlashData create a slashData
func NewSlashData(typ uint8, mainAddress common.Address, penaltyAmount *big.Int, records []*SlashWithdrawRecord, evidence *Evidence) (*SlashData, error) {
	if evidence == nil || evidence.Data == nil {
		return nil, errors.New("evidence error")
	}
	return &SlashData{Type: typ, MainAddress: mainAddress, Total: penaltyAmount, Records: records, Evidence: evidence}, nil
}

//DecodeRLP .
func (l *SlashData) DecodeRLP(s *rlp.Stream) error {
	var msg struct {
		Type          uint8
		MainAddress   common.Address
		PenaltyAmount *big.Int
		Records       []*SlashWithdrawRecord
		Evidence      *Evidence
	}

	if err := s.Decode(&msg); err != nil {
		return err
	}
	l.Type = msg.Type
	l.MainAddress = msg.MainAddress
	l.Total = msg.PenaltyAmount
	l.Records = msg.Records
	l.Evidence = msg.Evidence
	return nil
}

//EncodeRLP .
func (l SlashData) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{
		l.Type,
		l.MainAddress,
		l.Total,
		l.Records,
		l.Evidence,
	})
}

//Hash .
func (l *SlashData) Hash() (h common.Hash) {
	if hash := l.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}

	hw := sha3.NewKeccak256()
	rlp.Encode(hw, l)
	hw.Sum(h[:0])

	l.hash.Store(h)
	return h
}

//DecodeLogDataFromBytes .
func DecodeLogDataFromBytes(data []byte) (topic string, tags []string, payload interface{}, err error) {
	var logData LogData
	if err = rlp.DecodeBytes(data, &logData); err != nil {
		return "", nil, nil, err
	}

	switch logData.Topic {
	case LogTopicCreate:
		fallthrough
	case LogTopicChangeStatus:
		fallthrough
	case LogTopicDeposit:
		fallthrough
	case LogTopicUpdate:
		var val state.Validator
		err = rlp.DecodeBytes(logData.Data, &val)
		return logData.Topic, logData.Tags, &val, err

	case LogTopicWithdraw:
		fallthrough
	case LogTopicWithdrawResult:
		var record state.WithdrawRecord
		err = rlp.DecodeBytes(logData.Data, &record)
		return logData.Topic, logData.Tags, &record, err

	case LogTopicSettle:
		fallthrough
	case LogTopicRewards:
		var rewardDelta string
		err = rlp.DecodeBytes(logData.Data, &rewardDelta)
		return logData.Topic, logData.Tags, &rewardDelta, err

	case LogTopicSlashing:
		var slashData SlashData
		err = rlp.DecodeBytes(logData.Data, &slashData)
		return logData.Topic, logData.Tags, &slashData, err

	}
	return "", nil, nil, errors.New("unknown topic")
}
