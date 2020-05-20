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
	"testing"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
)

func TestNewPriorityMgr(t *testing.T) {
	pm := NewPriorityMgr()
	round := big.NewInt(2)
	roundIndex := uint32(1)
	sk, _ := crypto.GenerateKey()

	p1 := common.Hash{0x01}
	b1 := newBlock(round, roundIndex, p1, sk)
	r := pm.update(b1, b1.Hash(), p1, round, roundIndex)
	logging.Info("update", "r", r, "block", b1.Hash().String(), "priority", p1.String())

	p2 := common.Hash{0x02}
	b2 := newBlock(round, roundIndex, p2, sk)
	r = pm.update(b2, b2.Hash(), p2, round, roundIndex)
	logging.Info("update", "r", r, "block", b2.Hash().String(), "priority", p2.String())

	p, h, e := pm.getHashWithMaxPriority(round, roundIndex)
	logging.Info("getHashWithMaxPriority", "e", e, "block", h.String(), "priority", p.String())

	b3 := pm.getBlockInCache(b1.Hash(), p1)
	logging.Info("getBlockInCache", "b1 hash", b1.Hash().String(), "b3 hash", b3.Hash().String())

	r = pm.hasBlock(b2.Hash())
	logging.Info("hasBlock", "r", r, "block", b2.Hash().String())

	r = pm.hasPriority(b2.Hash(), p2, round, roundIndex)
	logging.Info("hasPriority", "r", r, "block", b2.Hash().String())

	r = pm.isMaxPriority(p1, round, roundIndex)
	logging.Info("isMaxPriority", "r", r, "priority", p1.String())

	r = pm.isMaxPriority(p2, round, roundIndex)
	logging.Info("isMaxPriority", "r", r, "priority", p2.String())

	pm.clearData(round)
	logging.Info("clearData")
	r = pm.hasBlock(b1.Hash())
	logging.Info("hasBlock", "r", r, "block", b1.Hash().String())
}

func newBlock(round *big.Int, roundIndex uint32, parent common.Hash, rawSk *ecdsa.PrivateKey) *types.Block {
	yp := params.Versions[params.YouCurrentVersion]
	tx1 := types.NewTransaction(1, common.BytesToAddress([]byte{0x11}), big.NewInt(111), 1111, big.NewInt(11111), []byte{0x11, 0x11, 0x11})
	tx2 := types.NewTransaction(2, common.BytesToAddress([]byte{0x22}), big.NewInt(222), 2222, big.NewInt(22222), []byte{0x22, 0x22, 0x22})
	tx3 := types.NewTransaction(3, common.BytesToAddress([]byte{0x33}), big.NewInt(333), 3333, big.NewInt(33333), []byte{0x33, 0x33, 0x33})
	txs := []*types.Transaction{tx1, tx2, tx3}

	block := types.NewBlock(&types.Header{Number: round, ParentHash: parent}, txs, nil)

	vrfSk, _ := secp256k1VRF.NewVRFSigner(rawSk)
	threshold := uint64(100)
	_, proof, _ := VrfSortition(vrfSk, seed, roundIndex, step, threshold, stake, totalStake)
	sortitionValue, proof, subUsers := VrfSortition(vrfSk, common.Hash{0x01}, roundIndex, step, threshold,
		stake, totalStake)
	priority := VrfComputePriority(sortitionValue, subUsers)
	consensusData := BlockConsensusData{
		Round:      round,
		RoundIndex: roundIndex,
		Seed:       common.Hash{0x01},
		//SeedProof:         []byte{0x01},
		//SortitionHash:     value,
		SortitionProof:     proof,
		Priority:           priority,
		SubUsers:           uint32(1),
		ProposerThreshold:  yp.ProposerThreshold,
		ValidatorThreshold: yp.ValidatorThreshold,
	}
	err := consensusData.SetSignature(rawSk)
	if err != nil {
		logging.Error("SetSignature failed", "err", err)
		return nil
	}

	// assemble consensus data and header
	extra, _ := PrepareConsensusData(block.Header(), &consensusData)
	header := block.Header()
	header.Consensus = extra
	header.MixDigest = types.UConMixHash

	block = block.WithSeal(header)

	return block
}
