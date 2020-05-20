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
	"errors"
	"math/big"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/rlp"
)

type BlockConsensusData struct {
	Round              *big.Int
	RoundIndex         uint32
	Seed               common.Hash
	SortitionProof     []byte
	Priority           common.Hash
	SubUsers           uint32
	Signature          []byte
	ProposerThreshold  uint64
	ValidatorThreshold uint64
	CertValThreshold   uint64
}

func (data *BlockConsensusData) IsValidSeed() (bool, error) {
	return true, nil
}

func (data *BlockConsensusData) IsValidRound() (bool, error) {
	return true, nil
}

func (data *BlockConsensusData) IsValidTime() (bool, error) {
	return true, nil
}

func (data *BlockConsensusData) SetSignature(key *ecdsa.PrivateKey) error {
	if len(data.Signature) > 0 {
		return nil
	}

	payload, err := rlp.EncodeToBytes(data)
	if err != nil {
		return err
	}
	result, err := Sign(key, payload)
	if err != nil {
		return err
	}
	data.Signature = result

	return nil
}

// extract public key from Signature
func (data *BlockConsensusData) GetPublicKey() (*ecdsa.PublicKey, error) {
	tmp := &BlockConsensusData{
		Round:              data.Round,
		RoundIndex:         data.RoundIndex,
		Seed:               data.Seed,
		SortitionProof:     data.SortitionProof,
		Priority:           data.Priority,
		SubUsers:           data.SubUsers,
		ProposerThreshold:  data.ProposerThreshold,
		ValidatorThreshold: data.ValidatorThreshold,
		CertValThreshold:   data.CertValThreshold,
	}
	payload, err := rlp.EncodeToBytes(tmp)
	if err != nil {
		return nil, err
	}
	pubKey, err := GetSignaturePublicKey(payload, data.Signature)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

var (
	// ErrInvalidConsensusData is returned if the length of extra-data is less than 32 bytes
	ErrInvalidConsensusData = errors.New("invalid consensus data")
)

// BlockConsensusData should be added to types.Block, so that node can get parameters from local blockchain
func GetConsensusDataFromHeader(header *types.Header) (*BlockConsensusData, error) {
	return ExtractConsensusData(header)
}

func ExtractConsensusData(header *types.Header) (*BlockConsensusData, error) {
	if header == nil || header.Consensus == nil {
		return nil, ErrInvalidConsensusData
	}

	data := &BlockConsensusData{}
	err := rlp.DecodeBytes(header.Consensus, data)
	if err != nil {
		return nil, err
	}

	return data, err
}

func PrepareConsensusData(header *types.Header, data *BlockConsensusData) ([]byte, error) {
	payload, err := rlp.EncodeToBytes(data)
	if err != nil {
		return nil, err
	}

	return payload, nil
}
