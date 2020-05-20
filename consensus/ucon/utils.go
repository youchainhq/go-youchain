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
	"math/big"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto/vrf"
	"github.com/youchainhq/go-youchain/logging"
)

func ComputeSeed(sk vrf.PrivateKey, round *big.Int, roundIndex uint32, preSeed common.Hash) (seed common.Hash, proof []byte) {
	// <seed, proof> <- VRF(preSeed || round)
	var concat []byte
	concat = append(concat, preSeed[:]...)
	concat = append(concat, round.Bytes()...)
	concat = append(concat, uint32ToBytes(roundIndex)...)

	seed, proof = sk.Evaluate(concat)

	if CompareCommonHash(seed, common.Hash{}) == 0 {
		logging.Error("======Get a zero Seed.", "round", round, "roundIndex", roundIndex, "preSeed", preSeed.String())
	}

	return seed, proof
}

func CompareCommonHash(p1, p2 common.Hash) int {
	pb1 := new(big.Int).SetBytes(p1[:])
	pb2 := new(big.Int).SetBytes(p2[:])
	return pb1.Cmp(pb2)
}

func GenerateEmptyBlock(parent *types.Block, sk *ecdsa.PrivateKey) *types.Block {
	// copy the parent consensus data as the header consensus data
	h := &types.Header{
		ParentHash: parent.Hash(),
		Number:     parent.Number().Add(parent.Number(), common.Big1()),
		GasRewards: big.NewInt(0),
		Subsidy:    big.NewInt(0),
		GasLimit:   core.CalcGasLimit(parent),
		MixDigest:  types.UConMixHash,
		TxHash:     types.EmptyRootHash,
		ValRoot:    parent.ValRoot(),
		Root:       parent.Root(),
	}

	prevConsensusData, err := GetConsensusDataFromHeader(parent.Header())
	if err != nil {
		return nil
	}

	// only change the Round, make sure every node can get the same result
	prevConsensusData.Round = big.NewInt(prevConsensusData.Round.Int64() + 1)
	prevConsensusData.RoundIndex = 1
	_ = prevConsensusData.SetSignature(sk)

	// assemble consensus data and header
	consensus, _ := PrepareConsensusData(h, prevConsensusData)

	h.Consensus = consensus

	return types.NewBlock(h, nil, nil)
}

func GetVoteFromBool(vote bool) uint32 {
	if vote {
		return uint32(1)
	} else {
		return uint32(0)
	}
}

func MillionSecond(time time.Time) int64 {
	return time.UnixNano() / 1e6
}
