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

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/crypto"
	secp256k1VRF "github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
)

type VerifyPriorityFn func(pubkey *ecdsa.PublicKey, data *ConsensusCommon) error

type VerifySortitionFn func(pubKey *ecdsa.PublicKey, data *SortitionData, lbType params.LookBackType) error

type GetLookBackValidatorFn func(round *big.Int, addr common.Address, lbType params.LookBackType) (*state.Validator, bool)

type SortitionData struct {
	Round      *big.Int
	RoundIndex uint32
	Step       uint32
	Proof      []byte
	Votes      uint32
}

func (s *Server) getLookBackSeed(round *big.Int, lbType params.LookBackType) (common.Hash, error) {
	if round == nil || round.Uint64() == 0 {
		logging.Error("invalid round", "round", round)
		return common.Hash{}, fmt.Errorf("invalid round: %s", round)
	}

	lookBack := s.GetLookBackBlockNumber(s.CurrentCaravelParams(), round, params.TurnToSeedType(lbType))
	lookBackHeader := s.chain.GetHeaderByNumber(lookBack.Uint64())
	if lookBackHeader == nil {
		err := fmt.Errorf("lookBackHeader not found. lookBack blockNumber: %s", lookBack.String())
		return common.Hash{}, err
	}

	prevConsensusData, err := GetConsensusDataFromHeader(lookBackHeader)
	if err != nil {
		logging.Error("get consensus data from header failed: ", "err", err)
		return common.Hash{}, err
	}
	lookBackSeed := prevConsensusData.Seed

	return lookBackSeed, nil
}

func (s *Server) getLookbackStakeInfo(round *big.Int, addr common.Address, isProposer bool, lbType params.LookBackType) (*big.Int, *big.Int, uint64, params.ValidatorKind, uint8, error) {
	if round == nil || round.Uint64() == 0 {
		err := fmt.Errorf("invalid round. Round: %s", round)
		logging.Error("getLookbackStakeInfo failed", "err", err)
		return big.NewInt(0), big.NewInt(0), uint64(0), params.KindValidator, params.ValidatorOffline, err
	}

	lookBack := s.GetLookBackBlockNumber(s.CurrentCaravelParams(), round, params.TurnToStakeType(lbType))
	lookBackHeader := s.chain.GetHeaderByNumber(lookBack.Uint64())
	if lookBackHeader == nil {
		err := fmt.Errorf("lookBackHeader not found. lookBack blockNumber: %s", lookBack.String())
		return &big.Int{}, &big.Int{}, 0, 0, params.ValidatorOffline, err
	}
	lbVld, err := s.chain.GetVldReader(lookBackHeader.ValRoot)
	if err != nil {
		return &big.Int{}, &big.Int{}, 0, 0, params.ValidatorOffline, err
	}
	v := lbVld.GetValidatorByMainAddr(addr)
	if v == nil {
		err := fmt.Errorf("GetValidatorByMainAddr failed. Round:%s, Addr:%s", round, addr.String())
		logging.Error("GetValidatorByMainAddr failed", "err", err)
		return big.NewInt(0), big.NewInt(0), uint64(0), params.KindValidator, params.ValidatorOffline, err
	}
	if v.Status == params.ValidatorOffline {
		err := fmt.Errorf("Node is offline. lookback: %d, Round: %s, Addr:%s", lookBack, round, addr.String())
		logging.Error("ValidatorOffline", "err", err)
		return big.NewInt(0), big.NewInt(0), uint64(0), params.KindValidator, v.Status, err
	}
	stat, err := lbVld.GetValidatorsStat()
	if err != nil {
		logging.Error("GetValidatorsStat failed.", "Round", round, "err", err)
		return &big.Int{}, &big.Int{}, 0, 0, v.Status, err
	}
	totalStake := stat.GetStakeByKind(v.Kind())
	if totalStake == nil {
		err := fmt.Errorf("GetStakeByKind failed. Round:%s, Addr:%s, Role:%d Kind: %d", round, addr.String(), v.Role, v.Kind())
		logging.Error("GetStakeByKind failed", "err", err)
		return big.NewInt(0), big.NewInt(0), uint64(0), params.KindValidator, v.Status, err
	}
	//threshold := uint64(float64(totalStake.Uint64()) * ValidatorProportionFloat(s.config.ValidatorProportion))
	var threshold uint64
	cp := s.CurrentCaravelParams()
	if isProposer {
		threshold = cp.ProposerThreshold
	} else if params.TurnToStakeType(lbType) == params.LookBackCertStake {
		// SPECIAL: use the CertValThreshold on the version of the cert look back header
		yp, ok := params.Versions[lookBackHeader.CurrVersion]
		if ok {
			threshold = yp.CertValThreshold
		}
	} else {
		threshold = cp.ValidatorThreshold
	}
	return v.Stake, totalStake, threshold, v.Kind(), v.Status, nil
}

func (s *Server) getLookbackValidatorsCount(round *big.Int, kind params.ValidatorKind, lbType params.LookBackType) (count uint64) {
	if round == nil || round.Uint64() == 0 {
		err := fmt.Errorf("invalid round. Round: %s", round)
		logging.Error("invalid round. Round", "err", err)
		return
	}

	lbVld, err := s.GetLookBackVldReader(s.CurrentCaravelParams(), round, lbType)
	if err != nil {
		logging.Error("GetLookBackStateDb failed.", "Round", round, "err", err)
		return
	}
	stat, err := lbVld.GetValidatorsStat()
	if err != nil {
		logging.Error("GetValidatorsStat failed.", "Round", round, "err", err)
		return
	}

	count = stat.GetCountOfKind(kind)

	return
}

func (s *Server) verifyPriority(pubkey *ecdsa.PublicKey, data *ConsensusCommon) error {
	lookBackSeed, err := s.getLookBackSeed(data.Round, params.LookBackPos)
	if err != nil {
		logging.Error("processCommitMessage failed.", "Round", data.Round, "RoundIndex", data.RoundIndex, "err", err)
		return err
	}

	// verify sortition
	pk, err := secp256k1VRF.NewVRFVerifier(pubkey)
	if err != nil {
		logging.Error("ucon: get pubKey failed: ", err)
		return fmt.Errorf("ucon: get pubKey failed: %d", err)
	}
	addr := crypto.PubkeyToAddress(*pubkey)
	stake, totalStake, _, kind, _, err := s.getLookbackStakeInfo(data.Round, addr, true, params.LookBackStake)
	if err != nil {
		return err
	}
	isValid, err := VrfVerifyPriority(pk, lookBackSeed, data.RoundIndex, data.Step, data.SortitionProof,
		data.Priority, data.SubUsers, s.CurrentCaravelParams().ProposerThreshold, stake, totalStake)
	if err != nil || !isValid {
		logging.Error("=======verify priority failed.", "Round", data.Round, "RoundIndex", data.RoundIndex,
			"Kind", kind, "Sub-Users", data.SubUsers, "step", data.Step, "proposerTh", s.CurrentCaravelParams().ProposerThreshold,
			"stake", stake, "totalStake", totalStake, "seed", lookBackSeed.String(), "addr", addr.String())
		return err
	}

	return nil
}

func (s *Server) verifySortition(pubKey *ecdsa.PublicKey, data *SortitionData, lbType params.LookBackType) error {
	pk, err := secp256k1VRF.NewVRFVerifier(pubKey)
	if err != nil {
		logging.Error("ucon: get pubKey failed: ", err)
		return err
	}

	addr := crypto.PubkeyToAddress(*pubKey)

	lookBackSeed, err := s.getLookBackSeed(data.Round, lbType)
	if err != nil {
		logging.Error("getLookBackSeed failed.", "Round", data.Round, "RoundIndex", data.RoundIndex, "err", err)
		return err
	}
	// verify sortition
	stake, totalStake, threshold, _, _, err := s.getLookbackStakeInfo(data.Round, addr, false, lbType)
	if err != nil {
		return err
	}
	isValid, err := VrfVerifySortition(pk, lookBackSeed, data.RoundIndex, data.Step, data.Proof, data.Votes, threshold, stake, totalStake)
	if err != nil || !isValid {
		if data.Round.Cmp(s.currentRound) < 0 || data.RoundIndex < s.roundIndex {
			return nil
		}
		logging.Error("=======verify sortition failed.", "Round", data.Round, "RoundIndex", data.RoundIndex,
			"step", data.Step, "validatorTh", threshold,
			"stake", stake, "totalStake", totalStake, "seed", lookBackSeed.String(), "addr", addr.String())
		return err
	}

	return nil
}

//GetLookBackBlockNumber return the stake-look-back block number for the specific block number.
//when round > config.StakeLookBack, it returns round - config.StakeLookBack
//else it always return 0 (the genesis block number)
func (s *Server) GetLookBackBlockNumber(cp *params.CaravelParams, num *big.Int, lbType params.LookBackType) *big.Int {
	if num.Sign() < 0 {
		panic("Error num")
	}
	//check if CaravelParams exist
	if lbType == params.LookBackPos || lbType == params.LookBackSeed || lbType == params.LookBackStake {
		if cp == nil {
			yp, err := s.chain.VersionForRound(num.Uint64())
			if err != nil {
				return nil
			}
			cp = &yp.CaravelParams
		}
	}

	lookBack := big.NewInt(0).Set(num)
	var cfg *big.Int
	switch lbType {
	case params.LookBackPos:
		fallthrough
	case params.LookBackSeed:
		cfg = big.NewInt(int64(cp.SeedLookBack))
	case params.LookBackStake:
		cfg = big.NewInt(int64(cp.StakeLookBack))
	case params.LookBackCert:
		fallthrough
	case params.LookBackCertSeed:
		cfg = big.NewInt(int64(params.ACoCHTFrequency))
	case params.LookBackCertStake:
		cfg = big.NewInt(int64(params.ACoCHTFrequency) * 2)
	}
	//cfg := big.NewInt(int64(s.config.StakeLookBack))
	if num.Cmp(cfg) > 0 {
		lookBack = lookBack.Sub(lookBack, cfg)
	} else {
		lookBack.SetInt64(0)
	}
	return lookBack
}

func (s *Server) GetLookBackBlockHash(cp *params.CaravelParams, num *big.Int, lbType params.LookBackType) (common.Hash, error) {
	lookBack := s.GetLookBackBlockNumber(cp, num, lbType)
	lookBackHeader := s.chain.GetHeaderByNumber(lookBack.Uint64())
	if lookBackHeader == nil {
		err := fmt.Errorf("lookBackHeader not found. num: %s lookBack blockNumber: %s", num.String(), lookBack.String())
		return common.Hash{}, err
	}
	return lookBackHeader.Hash(), nil
}

func (s *Server) GetLookBackVldReader(cp *params.CaravelParams, num *big.Int, lbType params.LookBackType) (state.ValidatorReader, error) {
	lookBack := s.GetLookBackBlockNumber(cp, num, lbType)
	if lookBack == nil {
		return nil, fmt.Errorf("can not get YOUChain parameters for round %v", num)
	}
	lookBackHeader := s.chain.GetHeaderByNumber(lookBack.Uint64())
	if lookBackHeader == nil {
		err := fmt.Errorf("lookBackHeader not found. lookBack blockNumber: %s", lookBack.String())
		return nil, err
	}
	return s.chain.GetVldReader(lookBackHeader.ValRoot)
}

func (s *Server) GetLookBackValidator(round *big.Int, addr common.Address, lbType params.LookBackType) (*state.Validator, bool) {
	if round == nil || round.Uint64() == 0 {
		err := fmt.Errorf("invalid round. Round: %s", round)
		logging.Error("getLookbackStakeInfo failed", "Round", round, "addr", addr.String(), "err", err)
		return nil, false
	}
	cp := s.CurrentCaravelParams()

	// check whether the lookback number is over the current height
	lookbackNum := s.GetLookBackBlockNumber(cp, round, params.TurnToSeedType(lbType))
	if s.currentRound.Uint64() <= lookbackNum.Uint64() {
		logging.Error("GetLookBackValidator failed.", "CurRound", s.currentRound, "Round", round, "lookbackNum", lookbackNum)
		return nil, true
	}

	// get validator info
	lookBack := s.GetLookBackBlockNumber(cp, round, params.TurnToStakeType(lbType))
	lookBackHeader := s.chain.GetHeaderByNumber(lookBack.Uint64())
	if lookBackHeader == nil {
		err := fmt.Errorf("lookBackHeader not found. lookBack blockNumber: %s", lookBack.String())
		logging.Error("getLookbackStakeInfo failed", "Round", round, "addr", addr.String(), "err", err)
		return nil, false
	}
	lbVld, err := s.chain.GetVldReader(lookBackHeader.ValRoot)
	if err != nil {
		logging.Error("GetVldReader failed", "Round", round, "addr", addr.String(), "err", err)
		return nil, false
	}
	v := lbVld.GetValidatorByMainAddr(addr)
	//lbVld, err := s.GetLookBackVldReader(cp, round, lbType)
	//if err != nil {
	//	logging.Error("GetLookBackVldReader failed", "Round", round, "addr", addr.String(), "err", err)
	//	return nil, false
	//}
	//v := lbVld.GetValidatorByMainAddr(addr)
	if v == nil {
		err := fmt.Errorf("GetValidatorByMainAddr failed. Round:%s, Addr:%s", round, addr.String())
		logging.Error("GetValidatorByMainAddr failed", "Round", round, "addr", addr.String(), "err", err)
		return nil, false
	}
	//logging.Debug("GetLookBackVal.", "CurRound", s.currentRound, "Round", round, "lookbackNum", lookbackNum)
	return v, false
}
