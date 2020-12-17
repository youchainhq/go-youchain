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
	"io"
	"math/big"
	"sync/atomic"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/rlp"
)

const (
	//EvidenceTypeDoubleSign name of duplicate vote
	EvidenceTypeDoubleSign = "doublesign"
	//EvidenceTypeInactive name of inactive
	EvidenceTypeInactive     = "inactive"
	EvidenceTypeDoubleSignV5 = "doublesignv5"
)

//Evidence the evidence of validator's action
type Evidence struct {
	Type string `json:"type"`
	Data []byte `json:"data"`
	addr atomic.Value
	data atomic.Value
}

//NewEvidence create a new evidence
func NewEvidence(data interface{}) Evidence {
	var typ string
	switch data.(type) {
	case EvidenceDoubleSign:
		typ = EvidenceTypeDoubleSign
	case EvidenceInactive:
		typ = EvidenceTypeInactive
	case EvidenceDoubleSignV5:
		typ = EvidenceTypeDoubleSignV5
	}
	body, err := rlp.EncodeToBytes(data)
	if err != nil {
		return Evidence{
			Type: typ,
			Data: nil,
		}
	}
	return Evidence{
		Type: typ,
		Data: body,
	}
}

var (
	_ rlp.Decoder = &EvidenceDoubleSign{}
	_ rlp.Encoder = &EvidenceDoubleSign{}
)

// EvidenceDoubleSign data of dup-vote
// Deprecated: using EvidenceDoubleSignV5 instead.
type EvidenceDoubleSign struct {
	Round      *big.Int
	RoundIndex uint32
	Signs      map[common.Hash][]byte
}

//DecodeRLP .
func (e *EvidenceDoubleSign) DecodeRLP(c *rlp.Stream) error {
	var data struct {
		Round      *big.Int
		RoundIndex uint32
		Signs      []struct {
			Hash []byte
			Sign []byte
		}
	}
	if err := c.Decode(&data); err != nil {
		return err
	}

	e.Round = data.Round
	e.RoundIndex = data.RoundIndex
	e.Signs = make(map[common.Hash][]byte)
	for _, item := range data.Signs {
		e.Signs[common.BytesToHash(item.Hash)] = item.Sign
	}
	return nil
}

// EncodeRLP implements rlp.Encoder.
func (e EvidenceDoubleSign) EncodeRLP(w io.Writer) error {
	var data struct {
		Round      *big.Int
		RoundIndex uint32
		Signs      []struct {
			Hash []byte
			Sign []byte
		}
	}
	data.Round = new(big.Int).Set(e.Round)
	data.RoundIndex = e.RoundIndex
	for h, s := range e.Signs {
		data.Signs = append(data.Signs, struct {
			Hash []byte
			Sign []byte
		}{Hash: h.Bytes(), Sign: s})
	}
	return rlp.Encode(w, []interface{}{data.Round, data.RoundIndex, data.Signs})
}

//EvidenceInactive data of inactive
type EvidenceInactive struct {
	Round      uint64
	Validators []common.Address
}

// EvidenceDoubleSignV5 is the data of dup-vote with bls signature.
type EvidenceDoubleSignV5 struct {
	Round      uint64
	RoundIndex uint32
	SignerIdx  uint32
	VoteType   uint8
	Signs      []*SignInfo
}

type SignInfo struct {
	Hash common.Hash
	Sign []byte
}
