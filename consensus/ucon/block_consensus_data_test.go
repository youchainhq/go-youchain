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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/rlp"
)

func TestConsensusDataInBlock(t *testing.T) {
	data := &BlockConsensusData{
		Round:      common.Big1(),
		RoundIndex: uint32(1),
		Seed:       common.Hash{0x1},
		//SeedProof:      []byte{0x1},
		//SortitionHash:  common.Hash{0x1},
		SortitionProof: []byte{0x1},
		Priority:       common.Hash{0x1},
	}

	header := &types.Header{}
	extra, err := PrepareConsensusData(header, data)
	if err != nil {
		t.Fatal(err)
	}

	header.Consensus = extra
	block := types.NewBlockWithHeader(header)

	blockRlp, err := rlp.EncodeToBytes(&block)
	if err != nil {
		t.Fatal(err)
	}

	blockRev := &types.Block{}
	_ = rlp.DecodeBytes(blockRlp, blockRev)

	dataRev, err := ExtractConsensusData(blockRev.Header())
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, dataRev.Round, common.Big1())
}

func TestExtractConsensusData(t *testing.T) {
	t.SkipNow() //run on need
	conBytes := hexutil.MustDecode("0xf84e8001a05d93025288dddb431e3f43e07c63d1a96a28bf033457c74ee3f4d8eed88d3cf601a0010000000000000000000000000000000000000000000000000000000000000001801a8207d0820fa0")
	data := &BlockConsensusData{}
	err := rlp.DecodeBytes(conBytes, data)
	if err != nil {
		t.Errorf("GetConsensusDataFromHeader failed. err: %v", err)
	}
	t.Log("ConsensusData", "Round", data.Round, "RI", data.RoundIndex, "Seed", data.Seed.String(),
		"SubUsers", data.SubUsers, "ProposerThreshold", data.ProposerThreshold, "ValidatorThreshold", data.ValidatorThreshold,
		"CertThreshold", data.CertValThreshold, "Priority", data.Priority.String())
}

func TestBlockConsensusData_GetPublicKey(t *testing.T) {
	sk, _ := crypto.GenerateKey()
	data := &BlockConsensusData{
		Round:      common.Big1(),
		RoundIndex: uint32(1),
		Seed:       common.Hash{0x1},
		//SeedProof:      []byte{0x1},
		//SortitionHash:  common.Hash{0x1},
		SortitionProof: []byte{0x1},
		Priority:       common.Hash{0x1},
	}

	err := data.SetSignature(sk)
	if err != nil {
		assert.NoError(t, err)
	}

	pk, err := data.GetPublicKey()
	if err != nil {
		assert.NoError(t, err)
	}
	cpk := crypto.CompressPubkey(pk)
	fmt.Println(common.Bytes2Hex(cpk))
}

func TestGetConsensusDataFromHeader(t *testing.T) {
	data := &BlockConsensusData{
		Round:      common.Big1(),
		RoundIndex: uint32(1),
		Seed:       common.Hash{0x1},
		//SeedProof:      []byte{0x1},
		//SortitionHash:  common.Hash{0x1},
		SortitionProof: []byte{0x1},
		Priority:       common.Hash{0x1},
	}

	header := &types.Header{}
	consensus, err := PrepareConsensusData(header, data)
	if err != nil {
		t.Fatal(err)
	}

	header.Consensus = consensus
	_, err = GetConsensusDataFromHeader(header)
	assert.NoError(t, err)
}
