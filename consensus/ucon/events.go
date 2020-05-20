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
	"math/big"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
)

//type ConsensusPriorityDataEvent struct {
//	// consensus message data
//	Data []byte
//}

//type RequestEvent struct {
//	Proposal Proposal
//}

type MessageEvent struct {
	Payload []byte
	Code    string
	Round   *big.Int
}

//type InvalidPeerEvent struct {
//	ID string
//}

type SendMessageEvent struct {
	Code    MsgType
	Payload []byte
	Round   *big.Int
}

type TransferMessageEvent struct {
	Code        MsgType
	Payload     []byte
	Round       *big.Int
	PayloadHash common.Hash
}

type ReceivedMsgEvent struct {
	Round      *big.Int
	RoundIndex uint32
	Addr       common.Address
	ReceivedAt time.Time
	SendAt     uint64
}

type PriorityMsgEvent struct {
	Msg *CachedPriorityMessage
	//FromCache bool
}

type ProposedBlockMsgEvent struct {
	Msg *CachedBlockMessage
	//FromCache bool
}

type VoteMsgEvent struct {
	Msg   *CachedVotesMessage
	VType VoteType
	//FromCache bool
}

type BlockProposalEvent struct {
	Block *types.Block
}

type ContextChangeEvent struct {
	Round       *big.Int
	RoundIndex  uint32
	Step        uint32
	Certificate bool
}

type CommitEvent struct {
	Round             *big.Int
	RoundIndex        uint32
	Block             *types.Block
	ChamberPrecommits VotesInfoForBlockHash
	HousePrecommits   VotesInfoForBlockHash
	ChamberCerts      VotesInfoForBlockHash
}

type RoundIndexChangeEvent struct {
	Round      *big.Int
	RoundIndex uint32
	BlockHash  common.Hash
	Priority   common.Hash
}

type UpdateExistedHeaderEvent struct {
	Round             *big.Int
	RoundIndex        uint32
	BlockHash         common.Hash
	ChamberPrecommits VotesInfoForBlockHash
	HousePrecommits   VotesInfoForBlockHash
}
