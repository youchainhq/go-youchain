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
	"reflect"
	"testing"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"github.com/youchainhq/go-youchain/logging"
)

func TestMessageBackForth(t *testing.T) {
	//p1 := &ConsensusCommon{big.NewInt(0), 0, common.Hash{0x1}, []byte{0x1}, 10, common.Hash{0x1}, common.Hash{0x1}}
	//
	//ecp1, _ := Encode(p1)
	//
	//m1 := Message{Code: msgPriorityProposal, Payload: ecp1}
	//
	//ecm1, _ := m1.Encode()
	//
	//dcm1, _ := Decode(ecm1)
	//
	//if dcm1.Code != msgPriorityProposal {
	//	t.Fatalf("expect msgPriorityProposal,got %d", MessageCodeToString(dcm1.Code))
	//}
	//
	//dcp1 := &ConsensusCommon{}
	//_ = dcm1.DecodePayload(dcp1)
	//
	//if !reflect.DeepEqual(dcp1.Priority, common.Hash{0x1}) {
	//	t.Fatalf("expect Priority = 1 ,got %d", dcp1.Priority)
	//}

	riHash := GenerateRoundIndexHash(12, 3)
	r1, r2 := GetInfoFromHash(riHash)
	logging.Info("GetInfoFromHash", "round", r1, "roundIndex", r2)

	roundIndex := uint32(2)

	// test msgPrevote
	sk, _ := crypto.GenerateKey()
	//voteBool := GetVoteFromBool(true)
	blockHash := common.Hash{0x3}
	//parentHash := common.Hash{0x2}
	threshold := uint64(100)

	vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)
	_, proof, subUsers := VrfSortition(vrfSk, seed, roundIndex, UConStepPrevote, threshold,
		stake, totalStake)

	payload := append(blockHash.Bytes(), uint32ToBytes(subUsers)...)
	signature, _ := Sign(sk, payload)

	vote := &SingleVote{
		Votes:     subUsers,
		Signature: signature,
		Proof:     proof,
	}
	msg := &BlockHashWithVotes{
		BlockHash: blockHash,
		//Votes:      make(VoteData, 1),
		Vote:       vote,
		Round:      big.NewInt(2),
		RoundIndex: roundIndex,
		//ParentHash: parentHash,
	}
	//msg.Votes[0].Votes = vote.Votes
	//msg.Votes[0].Proof = vote.Proof
	//msg.Votes[0].Signature = vote.Signature

	ecp2, err := Encode(msg)
	if err != nil {
		logging.Info("ecp2", "err", err)
	}
	m2 := Message{Code: msgPrevote, Payload: ecp2}

	ecm2, err := m2.Encode()
	if err != nil {
		logging.Info("ecm2", "err", err)
	}

	dcm2, err := Decode(ecm2)
	if err != nil {
		logging.Info("dcm2", "err", err)
	}
	if dcm2.Code != msgPrevote {
		t.Fatalf("expect msgPrevote,got %s", MessageCodeToString(dcm2.Code))
	}

	dcp2 := &BlockHashWithVotes{}
	err = dcm2.DecodePayload(dcp2)
	if err != nil {
		logging.Info("dcp2", "err", err)
	}

	if !reflect.DeepEqual(dcp2.BlockHash, common.Hash{0x3}) {
		t.Fatalf("expect BlockHash = 3 ,got %d", dcp2.BlockHash)
	}

	payload2 := append(dcp2.BlockHash.Bytes(), uint32ToBytes(dcp2.Vote.Votes)...)
	pubKey, _ := GetSignaturePublicKey(payload2, dcp2.Vote.Signature)
	pk2, _ := secp256k1VRF.NewVRFVerifier(pubKey)
	// verify sortition
	//addr := crypto.PubkeyToAddress(*pubKey)
	//stake := s.GetStakeForAccount(addr)
	isValid, err := VrfVerifySortition(pk2, seed, roundIndex, UConStepPrevote, dcp2.Vote.Proof, 1, threshold, stake, totalStake)
	if err != nil {
		logging.Error("VrfVerifySortition failed", "err", err)
	}
	logging.Info("VrfVerifySortition", "isValid", isValid)
}
