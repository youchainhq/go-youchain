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

package ucon

import (
	"io"
	"math/big"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/rlp"
)

type MsgType uint8

const (
	msgNone MsgType = iota
	msgPriorityProposal
	msgBlockProposal
	msgPrevote
	msgPrecommit
	msgNext
	msgCertificate

	MsgNamePriority  = "msgPriorityProposal"
	MsgNameBlock     = "msgBlockProposal"
	MsgNamePrevote   = "msgPrevote"
	MsgNamePrecommit = "msgPrecommit"
	MsgNameNext      = "msgNext"
	MsgNameCert      = "msgCertificate"
)

func MessageCodeToString(code MsgType) string {
	switch code {
	case msgPriorityProposal:
		return MsgNamePriority
	case msgBlockProposal:
		return MsgNameBlock
	case msgPrevote:
		return MsgNamePrevote
	case msgPrecommit:
		return MsgNamePrecommit
	case msgNext:
		return MsgNameNext
	case msgCertificate:
		return MsgNameCert
	}
	return ""
}

func StringToMessageCode(code string) MsgType {
	switch code {
	case MsgNamePriority:
		return msgPriorityProposal
	case MsgNameBlock:
		return msgBlockProposal
	case MsgNamePrevote:
		return msgPrevote
	case MsgNamePrecommit:
		return msgPrecommit
	case MsgNameNext:
		return msgNext
	case MsgNameCert:
		return msgCertificate
	}
	return msgNone
}

type VoteType uint8

const (
	VoteNone VoteType = iota
	Propose
	Prevote
	Precommit
	NextIndex
	Certificate
)

func VoteTypeToMsgCode(voteType VoteType) MsgType {
	switch voteType {
	case Prevote:
		return msgPrevote
	case Precommit:
		return msgPrecommit
	case NextIndex:
		return msgNext
	case Certificate:
		return msgCertificate
	}
	return msgNone
}

func MsgCodeToVoteType(msgCode MsgType) VoteType {
	switch msgCode {
	case msgPrevote:
		return Prevote
	case msgPrecommit:
		return Precommit
	case msgNext:
		return NextIndex
	case msgCertificate:
		return Certificate
	}
	return VoteNone
}

func VoteTypeToString(voteType VoteType) string {
	switch voteType {
	case Prevote:
		return "Prevote"
	case Precommit:
		return "Precommit"
	case NextIndex:
		return "Next"
	case Certificate:
		return "Certificate"
	}
	return "None"
}

//type SignatureHash [64]byte
//type ProofHash [128]byte

const (
	VoteMsgSize     = 384 //293
	PriorityMsgSize = 384 //261
)

// data structure for statistics
type SingleVote struct {
	VoterIdx  uint32
	Votes     uint32
	Signature []byte
	Proof     []byte // used to verify whether is a validator
}

type AddrVoteStatus struct {
	Hash        common.Hash
	Signature   []byte
	DoubleVoted bool
}

type VotesInfoForBlockHash map[common.Address]*SingleVote

func NewVotesInfoForBlockHash() VotesInfoForBlockHash {
	return make(map[common.Address]*SingleVote)
}

type ConsensusCommon struct {
	Round          *big.Int
	RoundIndex     uint32
	Step           uint32
	Priority       common.Hash
	SortitionProof []byte
	SubUsers       uint32
	BlockHash      common.Hash
	ParentHash     common.Hash
	Timestamp      uint64
}

type BlockHashWithVotes struct {
	Priority   common.Hash
	BlockHash  common.Hash
	Round      *big.Int
	RoundIndex uint32
	Vote       *SingleVote
	Timestamp  uint64
}

type MarkedBlockInfo struct {
	Priority   common.Hash
	BlockHash  common.Hash
	Round      *big.Int
	RoundIndex uint32
	Block      *types.Block
}

type Message struct {
	Code      MsgType
	Payload   []byte
	Signature []byte
}

func (m *Message) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{m.Code, m.Payload, m.Signature})
}

func (m *Message) DecodeRLP(s *rlp.Stream) error {
	var msg struct {
		Code      MsgType
		Payload   []byte
		Signature []byte
	}
	if err := s.Decode(&msg); err != nil {
		return err
	}

	m.Code = msg.Code
	m.Payload = msg.Payload
	m.Signature = msg.Signature
	return nil
}

func (m *Message) DecodePayload(val interface{}) error {
	return rlp.DecodeBytes(m.Payload, val)
}

func (m *Message) Encode() ([]byte, error) {
	return rlp.EncodeToBytes(m)
}

func (m *Message) EncodeNoSig() ([]byte, error) {
	return rlp.EncodeToBytes(&Message{
		Code:      m.Code,
		Payload:   m.Payload,
		Signature: []byte{},
	})
}

func (m *Message) PayloadHash() common.Hash {
	return crypto.Keccak256Hash(m.Payload)
}

func Encode(val interface{}) ([]byte, error) {
	return rlp.EncodeToBytes(val)
}

func Decode(b []byte) (*Message, error) {
	var msg Message
	err := rlp.DecodeBytes(b, &msg)

	if err != nil {
		return nil, err
	}
	return &msg, nil
}

// Lengths of RoundIndexHash in bytes.
const (
	// HashLength is the expected length of the hash
	RoundIndexHashLength = 12
)

type RoundIndexHash [RoundIndexHashLength]byte

func GenerateRoundIndexHash(round uint64, index uint32) RoundIndexHash {
	var m []byte

	m = append(m, uint64ToBytes(round)...)
	m = append(m, uint32ToBytes(index)...)

	var h RoundIndexHash
	h.SetBytes(m)
	return h
}

func GetInfoFromHash(h RoundIndexHash) (uint64, uint32) {
	return bytesToUint64(h[:8]), bytesToUint32(h[8:])
}

// SetBytes sets the hash to the value of b.
// If b is larger than len(h), b will be cropped from the left.
func (h *RoundIndexHash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-RoundIndexHashLength:]
	}

	copy(h[RoundIndexHashLength-len(b):], b)
}
