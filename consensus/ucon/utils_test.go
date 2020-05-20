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
	"testing"
	time2 "time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
)

func TestComputeSeed(t *testing.T) {
	//tmp := uint(500)
	//logging.Info("TestComputeSeed", "ValidatorProportionFloat", ValidatorProportionFloat(tmp))

	var test *BlockHashWithVotes
	ecm, err := Encode(test)
	logging.Info("test", "ecm", ecm, "err", err)

	sk, _ := crypto.GenerateKey()
	vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)

	seed, _ := ComputeSeed(vrfSk, big.NewInt(10), uint32(1), common.Hash{0x01})
	logging.Info(seed.String())

	seed1, _ := ComputeSeed(vrfSk, big.NewInt(10), uint32(1), common.Hash{0x01})
	logging.Info(seed1.String())

	seed2, _ := ComputeSeed(vrfSk, big.NewInt(11), uint32(1), seed)
	logging.Info(seed2.String())
}

func TestCompareCommonHash(t *testing.T) {
	sk, _ := crypto.GenerateKey()
	vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)

	seed, _ := ComputeSeed(vrfSk, big.NewInt(10), uint32(1), common.Hash{0x01})
	logging.Info(seed.String())

	seed1, _ := ComputeSeed(vrfSk, big.NewInt(10), uint32(1), common.Hash{0x01})
	logging.Info(seed1.String())

	seed2, _ := ComputeSeed(vrfSk, big.NewInt(11), uint32(1), seed)
	logging.Info(seed2.String())

	r1 := CompareCommonHash(seed, seed1)
	logging.Info("CompareCommonHash", "r1", r1)

	r2 := CompareCommonHash(seed1, seed2)
	logging.Info("CompareCommonHash", "r2", r2)

	r3 := CompareCommonHash(common.Hash{0x01}, common.Hash{})
	logging.Info("CompareCommonHash", "r3", r3)
}

func TestGenerateEmptyBlock(t *testing.T) {
	yp := params.Versions[params.YouCurrentVersion]
	data := &BlockConsensusData{
		Round:      common.Big1(),
		RoundIndex: uint32(1),
		Seed:       common.Hash{0x1},
		//SeedProof:         []byte{0x1},
		//SortitionHash:     common.Hash{0x1},
		SortitionProof:     []byte{0x1},
		Priority:           common.Hash{0x1},
		ProposerThreshold:  yp.ProposerThreshold,
		ValidatorThreshold: yp.ValidatorThreshold,
	}

	header := &types.Header{}
	extra, err := PrepareConsensusData(header, data)
	if err != nil {
		t.Fatal(err)
	}

	header.Consensus = extra
	emptyBlock := types.NewBlockWithHeader(header)

	sk, _ := crypto.GenerateKey()
	nextEmptyBlock1 := GenerateEmptyBlock(emptyBlock, sk)
	nextEmptyBlock2 := GenerateEmptyBlock(emptyBlock, sk)

	// Compare this two blocks
	if nextEmptyBlock1 != nil && nextEmptyBlock2 != nil {
		isEqual := nextEmptyBlock1.Hash() == nextEmptyBlock2.Hash()
		logging.Info("equal", "isEqual", isEqual)
	}
}

func TestGetVoteFromBool(t *testing.T) {
	vote := true
	voteInt := GetVoteFromBool(vote)
	logging.Info("GetVoteFromBool", voteInt, voteInt)
	logging.Info("uint32ToBytes", "uint32ToBytes", uint32ToBytes(voteInt))

	r := float64(3)*ValidatorProportionThreshold - 1
	if 1 > uint32(r) {
		logging.Info("1 > uint32(r)", "r", r)
	} else {
		logging.Info("error")
	}

	ucon := []byte("Ucon byzantine fault tolerance")
	tmp := common.BytesToHash(ucon)
	logging.Info(tmp.String())
}

//func TestGetBlockDelayTime(t *testing.T) {
//	totalErr := 0
//	for i := 0; i < 100; i++ {
//		sk1, _ := crypto.GenerateKey()
//		vrfSk1, _ := secp256k1VRF.NewVRFSigner(sk1)
//		sortitionValue1, _, subUsers1 := VrfSortition(vrfSk1, seed, uint32(1), step, threshold,
//			stake, totalStake)
//		p1 := VrfComputePriority(sortitionValue1, subUsers1)
//		time1 := GetBlockDelayTime(p1)
//
//		sk2, _ := crypto.GenerateKey()
//		vrfSk2, _ := secp256k1VRF.NewVRFSigner(sk2)
//		sortitionValue2, _, subUsers2 := VrfSortition(vrfSk2, seed, uint32(100), step, threshold,
//			stake, totalStake)
//		p2 := VrfComputePriority(sortitionValue2, subUsers2)
//		time2 := GetBlockDelayTime(p2)
//
//		if CompareCommonHash(p1, p2) > 0 && time1.Nanoseconds() >= time2.Nanoseconds() {
//			log.Error("1", time1, time2, p1.String(), p2.String())
//			totalErr += 1
//		} else if CompareCommonHash(p1, p2) == 0 && time1.Nanoseconds() != time2.Nanoseconds() {
//			log.Error("2", time1, time2, p1.String(), p2.String())
//			totalErr += 1
//		} else if CompareCommonHash(p1, p2) < 0 && time1.Nanoseconds() <= time2.Nanoseconds() {
//			log.Error("3", time1, time2, p1.String(), p2.String())
//			totalErr += 1
//		}
//	}
//	log.Info(totalErr)
//}

func TestMillionSecond(t *testing.T) {
	time := time2.Now()
	ms := MillionSecond(time)
	logging.Info("time", "ms", ms, "time", time)
}
