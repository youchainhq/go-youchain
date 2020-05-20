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
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"sync"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/youdb"
)

var (
	voteDataPrefix = []byte("v")
)

type VoteItem struct {
	VoteType   VoteType
	Round      *big.Int
	RoundIndex uint32
	Addr       common.Address
	Signature  []byte
}

type VoteDB struct {
	lock       sync.Mutex
	db         youdb.Database
	rawSk      *ecdsa.PrivateKey
	addr       common.Address
	round      *big.Int
	roundIndex uint32
	mark       map[VoteType]uint8
}

func NewVoteDB(db youdb.Database, rawSk *ecdsa.PrivateKey) *VoteDB {
	addr := crypto.PubkeyToAddress(rawSk.PublicKey)
	v := &VoteDB{db: db, rawSk: rawSk, addr: addr, mark: make(map[VoteType]uint8)}

	updateFn := func(vote *VoteItem) {
		if vote == nil || !VerifySignature(vote, v.addr) {
			return
		}
		if v.round == nil {
			v.round = vote.Round
			v.roundIndex = vote.RoundIndex
			v.mark[VoteType(vote.VoteType)] = 1
		} else if v.round.Cmp(vote.Round) > 0 || (v.round.Cmp(vote.Round) == 0 && v.roundIndex > vote.RoundIndex) {
			return
		} else if v.round.Cmp(vote.Round) == 0 && v.roundIndex == vote.RoundIndex {
			v.mark[VoteType(vote.VoteType)] = v.mark[VoteType(vote.VoteType)] + 1
		} else {
			v.mark = make(map[VoteType]uint8)
			v.mark[VoteType(vote.VoteType)] = 1
		}
	}

	prevote := ReadVoteData(v.db, v.addr, Prevote, 1)
	updateFn(prevote)

	precommit := ReadVoteData(v.db, v.addr, Precommit, 1)
	updateFn(precommit)

	nextIndex1 := ReadVoteData(v.db, v.addr, NextIndex, 1)
	updateFn(nextIndex1)

	nextIndex2 := ReadVoteData(v.db, v.addr, NextIndex, 2)
	updateFn(nextIndex2)

	return v
}

func (v *VoteDB) Stop() {
	v.lock.Lock()
	defer v.lock.Unlock()

	v.db.Close()
}

func (v *VoteDB) UpdateContext(round *big.Int, roundIndex uint32) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.round != nil && v.round.Cmp(round) == 0 && v.roundIndex == roundIndex {
		return
	}

	v.mark = make(map[VoteType]uint8)
	v.round = round
	v.roundIndex = roundIndex
}

func (v *VoteDB) UpdateVoteData(voteType VoteType, round *big.Int, roundIndex uint32) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.alreadyVoted(voteType, round, roundIndex) {
		return fmt.Errorf("alreadyVoted. round:%d, roundIndex:%d, type:%s", round, roundIndex, VoteTypeToString(voteType))
	}

	// update database
	payload := append(round.Bytes(), append(uint32ToBytes(roundIndex), int8ToBytes(uint8(voteType))...)...)
	signature, err := Sign(v.rawSk, payload)
	if err != nil {
		logging.Error("sign payload failed")
		return fmt.Errorf("sign payload failed")
	}

	vote := &VoteItem{VoteType: voteType, Round: round, RoundIndex: roundIndex, Addr: v.addr, Signature: signature}
	index := uint8(1) //v.mark[voteType] + 1
	if v.round != nil && v.round.Cmp(round) == 0 && v.roundIndex == roundIndex {
		index = v.mark[voteType] + 1
	}
	data, err := rlp.EncodeToBytes(vote)
	if err != nil {
		logging.Crit("Failed to RLP vote", "err", err, "data", data)
		return fmt.Errorf("Failed to RLP vote. %v", err)
	}

	key := AddrTypeKey(v.addr, voteType, index)

	err = v.db.Put(key, data)
	if err != nil {
		logging.Crit("Failed to store vote", "err", err)
		return fmt.Errorf("Failed to store vote. %v", err)
	}

	//test := ReadVoteData(v.db, v.addr, voteType, index)
	//logging.Info("ReadResult", "round", test.Round, "roundIndex", test.RoundIndex, "index", index, "type", voteType, "addr", v.addr.String())

	// update mark
	if v.round != nil && v.round.Cmp(round) != 0 || v.roundIndex != roundIndex {
		v.mark = make(map[VoteType]uint8)
	}
	v.round = round
	v.roundIndex = roundIndex
	v.mark[voteType] = v.mark[voteType] + 1
	return nil
}

func (v *VoteDB) ExistVoteData(voteType VoteType, round *big.Int, roundIndex uint32) bool {
	v.lock.Lock()
	defer v.lock.Unlock()

	return v.alreadyVoted(voteType, round, roundIndex)
}

func (v *VoteDB) alreadyVoted(voteType VoteType, round *big.Int, roundIndex uint32) bool {
	if v.round != nil && v.round.Cmp(round) == 0 {
		if v.roundIndex > roundIndex ||
			(v.roundIndex == roundIndex && voteType == NextIndex && v.mark[voteType] == 2) ||
			(v.roundIndex == roundIndex && voteType != NextIndex && v.mark[voteType] == 1) {
			return true
		}
	}

	return false
}

func AddrTypeKey(address common.Address, voteType VoteType, index uint8) []byte {
	return append(voteDataPrefix, append(address.Bytes(), append(int8ToBytes(uint8(voteType)), int8ToBytes(index)...)...)...)
}

func ReadVoteData(db youdb.Database, address common.Address, voteType VoteType, index uint8) *VoteItem {
	data, _ := db.Get(AddrTypeKey(address, voteType, index))
	if len(data) == 0 {
		return nil
	}
	vote := new(VoteItem)
	if err := rlp.Decode(bytes.NewReader(data), vote); err != nil {
		logging.Error("Invalid vote RLP", "err", err)
		return nil
	}
	logging.Info("ReadVote", "round", vote.Round, "roundIndex", vote.RoundIndex, "type", vote.VoteType, "index", index, "addr", address.String())

	return vote
}

func VerifySignature(vote *VoteItem, address common.Address) bool {
	payload := append(vote.Round.Bytes(), append(uint32ToBytes(vote.RoundIndex), int8ToBytes(uint8(vote.VoteType))...)...)
	pubKey, err := GetSignaturePublicKey(payload, []byte(vote.Signature))
	if err != nil {
		logging.Error("get Signature public key failed.", "err", err)
		return false
	}
	addr := crypto.PubkeyToAddress(*pubKey)
	if addr != address {
		logging.Error("ParseFailed", "oriAddr", addr, "curAddr", address.String())
		return false
	}
	return true
}
