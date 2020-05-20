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
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"

	"github.com/stretchr/testify/assert"
)

var (
	//sk, _ = crypto.GenerateKey()
	//vrfSk, _ = secp256k1VRF.NewVRFSigner(sk)
	//seed       = common.Hash{0x01}
	step = uint32(1)
	//threshold  = uint64(DefaultValidatorThreshold)
	//stake      = big.NewInt(30)
	//totalStake = big.NewInt(100)
)

func getConsensusCommonData() (*ecdsa.PrivateKey, *ConsensusCommon) {
	sk, _ := crypto.GenerateKey()
	vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)
	//seed := common.Hash{0x00001}
	//step := UConStepGossipHash
	//threshold := uint64(DefaultValidatorThreshold)
	//stake := big.NewInt(10)
	//totalStake := big.NewInt(100)

	// 1. compute sortition
	sortitionValue, proof, subUsers := VrfSortition(vrfSk, seed, uint32(1), step, threshold,
		stake, totalStake)

	// 2. construct message
	leaderHash := &ConsensusCommon{
		Round:          big.NewInt(0),
		RoundIndex:     uint32(1),
		Step:           step,
		Priority:       VrfComputePriority(sortitionValue, subUsers),
		SortitionProof: proof,
		SubUsers:       subUsers,
		BlockHash:      common.Hash{0x1},
		ParentHash:     common.Hash{0x01},
	}
	return sk, leaderHash
}

func TestServer_VerifyPriority(t *testing.T) {
	sk, leaderHash := getConsensusCommonData()

	// 3. compose typical message
	ecp1, _ := Encode(leaderHash)
	m := Message{Code: msgPriorityProposal, Payload: ecp1}

	// 4. append signature
	signature, _ := Sign(sk, ecp1)
	m.Signature = signature
	ecm, _ := m.Encode()

	// 5. decode typical message
	dcm, _ := Decode(ecm)

	// 6. extract public key from signature
	pubKey, _ := GetSignaturePublicKey(dcm.Payload, dcm.Signature)
	pk, _ := secp256k1VRF.NewVRFVerifier(pubKey)

	// 7. get message info
	dcp := &ConsensusCommon{}
	_ = dcm.DecodePayload(dcp)

	// 8. verify priority
	isValid, _ := VrfVerifyPriority(pk, seed, uint32(1), step, dcp.SortitionProof,
		dcp.Priority, dcp.SubUsers, threshold, stake, totalStake)
	fmt.Println(isValid)
}

type chainReader struct {
}

func (c *chainReader) VersionForRound(round uint64) (*params.YouParams, error) {
	yp := params.Versions[params.YouCurrentVersion]
	return &yp, nil
}

func TestNewMessageHandler(t *testing.T) {
	loops := 100
	if testing.Short() {
		loops = 10
	}

	reader := &chainReader{}
	yp, _ := reader.VersionForRound(0)
	sk, _ := crypto.GenerateKey()
	//vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)
	eventMux := new(event.TypeMux)
	mh := NewMessageHandler(sk, eventMux, getLookBackValidator, processReceivedMsg,
		processPriorityMessage, processProposedBlockMsg, processVoteMsg)
	mh.Start()

	ticker := time.NewTicker(yp.ConsensusTimeout)
	defer ticker.Stop()
	round := big.NewInt(1)
	roundIndex := uint32(1)
	count := uint32(1)
	num := 0
	for {
		select {
		case <-ticker.C:
			eventMux.AsyncPost(ContextChangeEvent{Round: round, RoundIndex: roundIndex, Step: count})
			if count > UConStepStart && count <= UConStepPrecommit {
				sendPriorityMsg(round, roundIndex, eventMux)
				handleMsg(mh)
			}
			count += 1
			if count > UConStepPrecommit+1 {
				round.SetUint64(round.Uint64() + 1)
				count = uint32(1)
			}
			num += 1
			if num > loops {
				return
			}
		}
	}
}

func sendPriorityMsg(round *big.Int, roundIndex uint32, eventMux *event.TypeMux) {
	priorityMsg := ConsensusCommon{
		Round:          round,
		RoundIndex:     roundIndex,
		Step:           UConStepProposal,
		Priority:       common.Hash{0x11},
		SortitionProof: []byte{0x12},
		SubUsers:       uint32(1),
		BlockHash:      common.Hash{0x14},
		ParentHash:     common.Hash{0x13},
	}

	ecp, err := Encode(priorityMsg)
	if err != nil {
		logging.Error("Encode priority message failed.", "err", err)
	}

	// gossip priority messages
	eventMux.AsyncPost(SendMessageEvent{Code: msgPriorityProposal, Payload: ecp, Round: round})
}

func handleMsg(mh *MessageHandler) {
	priorityMsg := ConsensusCommon{
		Round:          mh.round,
		RoundIndex:     mh.roundIndex,
		Step:           UConStepProposal,
		Priority:       common.Hash{0x21},
		SortitionProof: []byte{0x22},
		SubUsers:       uint32(1),
		BlockHash:      common.Hash{0x24},
		ParentHash:     common.Hash{0x23},
	}

	ecp, _ := Encode(priorityMsg)

	m := Message{Code: msgPriorityProposal, Payload: ecp}
	signature, _ := Sign(mh.rawSk, ecp)
	m.Signature = signature
	ecm, _ := m.Encode()

	mh.HandleMsg(ecm, time.Now())
}

func getLookBackValidator(round *big.Int, addr common.Address, lbType params.LookBackType) (*state.Validator, bool) {
	if round == nil || round.Uint64() == 0 {
		err := fmt.Errorf("invalid round. Round: %s", round)
		logging.Error("getLookbackStakeInfo failed", "err", err)
		return nil, false
	}

	v := &state.Validator{}
	return v, false
}

func processReceivedMsg(ev ReceivedMsgEvent) (error, bool) {
	return nil, true
}

func processProposedBlockMsg(msg *CachedBlockMessage, status MsgReceivedStatus) (error, bool) {
	return nil, false
}

func processPriorityMessage(msg *CachedPriorityMessage, status MsgReceivedStatus) (error, bool) {
	return nil, false
}

func processVoteMsg(ev VoteMsgEvent, status MsgReceivedStatus) (error, bool) {
	return nil, false
}

//func TestServer_GetEncodedCommonData(t *testing.T) {
//	server := getServer()
//	server.UpdateContext()
//
//	ecp, _ := server.GetEncodedCommonData(common.Hash{0x002}, UConStepGossipHash)
//
//	server.ConstructCommonData(common.Hash{0x002}, UConStepGossipHash)
//}

//func TestServer_TransferMsg(t *testing.T) {
//	seed := common.Hash{0x00001}
//	step := UConStepGossipHash
//	threshold := uint64(DefaultValidatorThreshold)
//	stake := big.NewInt(10)
//	totalStake := big.NewInt(100)
//
//	sk, leaderHash := getConsensusCommonData()
//
//	// 3. compose typical message
//	ecp1, _ := Encode(leaderHash)
//	m := Message{Code: msgPriorityProposal, Payload: ecp1}
//
//	// 4. append signature
//	signature, _ := Sign(sk, ecp1)
//	m.Signature = signature
//	ecm, _ := m.Encode()
//}

func TestBlockHashWithVotes(t *testing.T) {
	votesMsg := &BlockHashWithVotes{}
	assert.NotNil(t, votesMsg)
	assert.Nil(t, votesMsg.Round)
}
