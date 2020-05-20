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
	"math/rand"
	"testing"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/common/math"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"

	"github.com/stretchr/testify/assert"
)

func init() {
	params.InitNetworkId(params.NetworkIdForTestCase)
}

/**
mark: here to generate block header extra
*/
func TestGenesisBlockHeader(t *testing.T) {
	sk, _ := crypto.GenerateKey()
	vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)

	seed, _ := ComputeSeed(vrfSk, big.NewInt(0), uint32(1), common.Hash{0x01})
	data := &BlockConsensusData{
		Round:              common.Big0(),
		RoundIndex:         uint32(1),
		Seed:               seed,
		SortitionProof:     []byte{0x1},
		Priority:           common.Hash{0x1},
		SubUsers:           uint32(1),
		Signature:          []byte{},
		ProposerThreshold:  uint64(26),
		ValidatorThreshold: uint64(2000),
		CertValThreshold:   uint64(4000),
	}

	header := &types.Header{}
	extra, err := PrepareConsensusData(header, data)
	if err != nil {
		t.Fatal(err)
	}
	logging.Info("PrepareConsensusData", "extra", hexutil.Encode(extra[:]))

	tmp := &BlockConsensusData{}
	err = rlp.DecodeBytes(extra, tmp)
	assert.NoError(t, err)
}

func TestVRF(t *testing.T) {
	loops := uint32(20000)
	if testing.Short() {
		loops = 100
	}

	yp := params.Versions[params.YouCurrentVersion]
	failedSeed := common.HexToHash("0x426d37d848d43b618e83e0ce2c7d4e9edab940d2b03c49b6e7733e40394fd1a5")
	logging.Info("failedSeed", "Seed", failedSeed.String())
	for i := uint32(1); i < loops; i++ {
		sk, _ := crypto.GenerateKey()
		vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)
		vrfPk, _ := secp256k1VRF.NewVRFVerifier(&sk.PublicKey)

		_, proof, _ := VrfSortition(vrfSk, failedSeed, i, UConStepProposal, yp.ProposerThreshold,
			big.NewInt(10), big.NewInt(100))

		var mtest = MakeM(failedSeed, UConStepProposal, i)
		_, err := vrfPk.ProofToHash(mtest, proof)
		if err != nil {
			logging.Error("ProofToHash", "failed", i)
		}
	}
}

func TestIsValidator(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}
	rand.Seed(time.Now().Unix())
	nodesCount := 100
	stakeList := make([]int64, nodesCount)
	totalStake := int64(0)
	for i := 0; i < nodesCount; i++ {
		stake := rand.Int63n(int64(1000))
		stakeList[i] = stake
		totalStake += stake
	}
	logging.Info("stakeList", "stakeList", stakeList)
	failedSeed := common.HexToHash("0x426d37d848d43b618e83e0ce2c7d4e9edab940d2b03c49b6e7733e40394fd1a5")

	//proposerThreshold := uint64(10)
	//minimalProposer := 1
	//lessThanMin := 0
	//for i := 0; i < 100; i++ {
	//	// get proposer count
	//	proposer := 0
	//	for i := 0; i < nodesCount; i++ {
	//		sk, _ := crypto.GenerateKey()
	//		vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)
	//
	//		_, _, subUsers := VrfSortition(vrfSk, failedSeed, uint32(1), UConStepProposal, proposerThreshold,
	//			big.NewInt(stakeList[i]), big.NewInt(totalStake))
	//		if subUsers > 0 {
	//			proposer += 1
	//		}
	//	}
	//	log.Info("proposer", proposer)
	//	if proposer < minimalProposer {
	//		lessThanMin += 1
	//	}
	//}
	//log.Info("Less than minimal proposer", lessThanMin)

	validatorThreshold := int64(55)
	minimalVotes := uint32(float64(validatorThreshold)*ValidatorProportionThreshold - 1) //float64(validatorThreshold) * ValidatorProportionThreshold
	logging.Info("minimalVotes", "Minimal votes", minimalVotes)
	failCount := 0
	for i := 0; i < 1000; i++ {
		// get validator count
		validators := 0
		for j := 0; j < nodesCount; j++ {
			sk, _ := crypto.GenerateKey()
			vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)

			_, _, subUsers := VrfSortition(vrfSk, failedSeed, uint32(1), UConStepPrevote, uint64(validatorThreshold),
				big.NewInt(stakeList[j]), big.NewInt(totalStake))
			if subUsers > 0 {
				validators += 1 //int(subUsers)
			}
		}
		logging.Info("validators", "validator", validators)
		if uint32(validators) <= minimalVotes {
			failCount += 1
			logging.Error("not enough votes", "validators", validators)
		}
	}
	logging.Info("Fail count", "failCount", failCount)
}

//func (s *Server) testVerify(block *types.Block) {
//	// 1. 封装
//	payload, _ := Encode(block)
//	signature, _ := Sign(s.rawSk, payload)
//	m := Message{Code: msgBlockProposal, Payload: payload, Signature: signature}
//	ecm, _ := m.Encode()
//
//	// 2. 还原
//	dcm, _ := Decode(ecm)
//	pubKey, _ := GetSignaturePublicKey(dcm.Payload, dcm.Signature)
//	pk, _ := secp256k1VRF.NewVRFVerifier(pubKey)
//
//	// 3. 得到message
//	block2 := &types.Block{}
//	_ = dcm.DecodePayload(block2)
//	consensusData, _ := GetConsensusDataFromHeader(block.Header())
//	msg := &CachedBlockMessage{
//		data:       ecm,
//		msg:        dcm,
//		pubKey:     pubKey,
//		vrfPK:      pk,
//		block:      block,
//		round:      consensusData.Round,
//		roundIndex: consensusData.RoundIndex,
//	}
//
//	// 4. 验证
//	addr := crypto.PubkeyToAddress(*msg.pubKey)
//	stake := s.GetStakeForAccount(addr)
//	rawAddr := crypto.PubkeyToAddress(s.rawSk.PublicKey)
//	rawstake := s.GetStakeForAccount(rawAddr)
//	log.Info("===============", "addr1", addr.String())
//	log.Info("===============", "addr2", rawAddr.String())
//	log.Info("===============", "stake", stake.String(), "rawStake", rawstake.String())
//
//	consensusData2, _ := GetConsensusDataFromHeader(msg.block.Header())
//	if CompareCommonHash(consensusData.Priority, consensusData2.Priority) != 0 {
//		return
//	}
//
//	// verify priority, also do sortition verification
//	isValid, err := VrfVerifyPriority(msg.vrfPK, s.lookBackSeed, msg.roundIndex, UConStepProposal, consensusData2.SortitionProof,
//		consensusData2.Priority, consensusData2.SubUsers, DefaultProposerThreshold, stake, s.context.totalStake)
//	if err != nil || !isValid {
//		log.Error("msgBlockProposal, priority is invalid.", "Round", msg.round, "Index", msg.roundIndex, "hash", msg.block.Hash().String())
//		return
//	}
//}
//
//func (s *Server) testComplete() {
//	sortitionValue, proof, subUsers := VrfSortition(s.vrfSk, s.lookBackSeed, s.roundIndex, UConStepProposal,
//		DefaultProposerThreshold, s.context.stake, s.context.totalStake)
//	priority := VrfComputePriority(sortitionValue, subUsers)
//	// construct consensus data which should be added to the header of the proposed block
//	consensusData := &BlockConsensusData{
//		Round:          s.currentRound,
//		RoundIndex:     s.roundIndex,
//		Seed:           s.context.seed,
//		SeedProof:      s.context.seedProof,
//		SortitionHash:  sortitionValue,
//		SortitionProof: proof,
//		ProposedTime:   big.NewInt(time.Now().Unix()),
//		Priority:       priority,
//		SubUsers:       subUsers,
//	}
//
//	payload, _ := Encode(consensusData)
//	signature, _ := Sign(s.rawSk, payload)
//	pubKey, _ := GetSignaturePublicKey(payload, signature)
//	pk, _ := secp256k1VRF.NewVRFVerifier(pubKey)
//	addr := crypto.PubkeyToAddress(*pubKey)
//	stake := s.GetStakeForAccount(addr)
//
//	// verify priority, also do sortition verification
//	isValid, err := VrfVerifyPriority(pk, s.lookBackSeed, s.roundIndex, UConStepProposal, consensusData.SortitionProof,
//		consensusData.Priority, consensusData.SubUsers, DefaultProposerThreshold, stake, s.context.totalStake)
//	if err != nil || !isValid {
//		log.Error("msgBlockProposal, priority is invalid.")
//		return
//	}
//}
//
//func (s *Server) testPriority(hash common.Hash) {
//	sortitionValue, proof, subUsers := VrfSortition(s.vrfSk, s.lookBackSeed, s.roundIndex, UConStepProposal, DefaultProposerThreshold,
//		s.context.stake, s.context.totalStake)
//	priority := VrfComputePriority(sortitionValue, subUsers)
//	priorityMsg := &ConsensusCommon{
//		Round:          s.currentRound,
//		RoundIndex:     s.roundIndex,
//		Step:           step,
//		Priority:       priority,
//		SortitionProof: proof,
//		SubUsers:       subUsers,
//		BlockHash:      hash,
//		ParentHash:  s.context.lastBlockHash,
//	}
//	payload, _ := Encode(priorityMsg)
//	signature, _ := Sign(s.rawSk, payload)
//	m := Message{Code: msgPriorityProposal, Payload: payload, Signature: signature}
//	ecm, _ := m.Encode()
//
//	// 2. 还原
//	dcm, _ := Decode(ecm)
//	pubKey, _ := GetSignaturePublicKey(dcm.Payload, dcm.Signature)
//	pk, _ := secp256k1VRF.NewVRFVerifier(pubKey)
//
//	// 3. 得到message
//	dcp := &ConsensusCommon{}
//	dcm.DecodePayload(dcp)
//	msg := &CachedPriorityMessage{
//		data:      ecm,
//		msg:       dcm,
//		pubKey:    pubKey,
//		vrfPK:     pk,
//		consensus: dcp,
//	}
//
//	// 4. 验证
//	addr := crypto.PubkeyToAddress(*msg.pubKey)
//	stake := s.GetStakeForAccount(addr)
//	rawAddr := crypto.PubkeyToAddress(s.rawSk.PublicKey)
//	rawstake := s.GetStakeForAccount(rawAddr)
//	log.Info("===============", "addr1", addr.String())
//	log.Info("===============", "addr2", rawAddr.String())
//	log.Info("===============", "stake", stake.String(), "rawStake", rawstake.String())
//
//	if CompareCommonHash(dcp.Priority, priorityMsg.Priority) != 0 {
//		return
//	}
//
//	// verify priority, also do sortition verification
//	err := s.verifyPriority(msg.vrfPK, msg.consensus, UConStepProposal, stake)
//	if err != nil {
//		return
//	}
//
//	isValid, err := VrfVerifyPriority(msg.vrfPK, s.lookBackSeed, dcp.RoundIndex, UConStepProposal, dcp.SortitionProof,
//		dcp.Priority, dcp.SubUsers, DefaultValidatorThreshold, stake, s.context.totalStake)
//	if err != nil || !isValid {
//		return
//	}
//}

func TestGetLookBackBlockNumber(t *testing.T) {
	type data struct {
		round *big.Int
		want  *big.Int
	}
	yp := params.Versions[params.YouCurrentVersion]
	//when round > config.StakeLookBack, it returns round - config.StakeLookBack
	//else it always return 0 (the genesis block number)
	d := int64(yp.StakeLookBack)
	large := big.NewInt(0).SetUint64(math.MaxUint64)
	testdata := []data{
		{round: big.NewInt(1), want: big.NewInt(0)},
		{round: big.NewInt(10), want: big.NewInt(0)},
		{round: big.NewInt(d), want: big.NewInt(0)},
		{round: big.NewInt(d + 1), want: big.NewInt(1)},
		{round: big.NewInt(0).Add(big.NewInt(d), large), want: large},
	}

	server := &Server{}
	for _, dt := range testdata {
		got := server.GetLookBackBlockNumber(&yp.CaravelParams, dt.round, params.LookBackStake)
		if got.Cmp(dt.want) != 0 {
			t.Errorf("want: %s, got: %s \n", dt.want.String(), got.String())
		}
	}
}
