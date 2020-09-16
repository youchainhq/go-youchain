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
	//t.SkipNow() //run on need
	conBytes := hexutil.MustDecode("0xf90115831d769801a04624b50015bce4705af4ebd7c56bebdd5eaf0916570c7cec13ae96243543e5a0b881826eceb47192dfc31311a6d9db6407fab65e1c69e41e52e578f6cd16497eaa1e91b1dad209149d577df54cf8b0ad907b587b344c4ce6ab97c80c67cb0ad727c1048783bb2c91d65d50f00bb86f2c54469b91de6fae6c2131bd516fa894a3f707e10584cf0a0bc2677d891d3fda6167971e14dda38ff01a10dcee700503265e152fa0f99032db169aac312afb925226c541ad06f3cb4b3ca8073772f0f9afea48e80001b8419510bea54cddda37d4758ed07644745a11b66be704e16ff861d34b07f96f0b041349815595d9e61434208c29985199126246d3213d0207e25537fac26742d20b001a8207d0820fa0")
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
