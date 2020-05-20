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

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
)

func TestNewSortitionManager(t *testing.T) {
	rawSk, _ := crypto.GenerateKey()
	vrfSk, _ := secp256k1VRF.NewVRFSigner(rawSk)
	addr := crypto.PubkeyToAddress(rawSk.PublicKey)
	sm := NewSortitionManager(vrfSk, getStake, getLookBackSeed, addr)

	round := big.NewInt(1)
	roundIndex := uint32(1)
	sm.ClearStepView(round)

	sm.isProposer(round, roundIndex)
	sm.isValidator(round, roundIndex, UConStepPrevote, params.LookBackStake)

	sv := sm.GetStepView(round, roundIndex, UConStepPrevote)
	logging.Info("GetStepView.", "Subusers", sv.SubUsers, "Priority", sv.Priority.String())
}

func getStake(round *big.Int, addr common.Address, isProposer bool, lbtype params.LookBackType) (*big.Int, *big.Int, uint64, params.ValidatorKind, uint8, error) {
	return stake, totalStake, uint64(0), params.KindValidator, params.ValidatorOnline, nil
}

func getLookBackSeed(round *big.Int, lbtype params.LookBackType) (common.Hash, error) {
	return common.Hash{0x11}, nil
}
