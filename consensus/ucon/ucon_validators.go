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
	"sort"
	"strings"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
)

type UconValidators struct {
	RoundIndex        uint32
	ChamberCommitters []SingleVote
	HouseCommitters   []SingleVote
	ChamberCerts      []SingleVote
	SCAggrSig         []byte // bls aggregated signature for ChamberCommitters
	MCAggrSig         []byte // bls aggregated signature for HouseCommitters
	CCAggrSig         []byte // bls aggregated signature for ChamberCerts
}

func NewUconValidators(ev CommitEvent, backType params.LookBackType) *UconValidators {
	uc := &UconValidators{RoundIndex: ev.RoundIndex}

	appendFn := func(data VotesInfoForBlockHash, voteType VoteType, kind params.ValidatorKind) []SingleVote {
		votes := make([]SingleVote, 0, len(data))
		count := uint32(0)
		for _, value := range data {
			votes = append(votes, *value)
			count += value.Votes
		}
		//log.Info("CommitVotes.", VoteTypeToString(voteType), ValidateTypeToString(kind), count)
		return votes
	}

	if backType == params.LookBackCert {
		uc.ChamberCerts = appendFn(ev.ChamberCerts, Certificate, params.KindChamber)
	} else {
		//uc.ChamberValidators = appendFn(ev.ChamberPrevotes, Prevote, params.KindChamber)
		uc.ChamberCommitters = appendFn(ev.ChamberPrecommits, Precommit, params.KindChamber)
		//uc.HouseValidators = appendFn(ev.HousePrevotes, Prevote, params.KindHouse)
		uc.HouseCommitters = appendFn(ev.HousePrecommits, Precommit, params.KindHouse)
	}

	return uc
}

func (uc *UconValidators) ValidatorsToByte() ([]byte, error) {
	data, err := rlp.EncodeToBytes(uc)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// ExtractUconValidators extracts all values of the UconValidators from the header. It returns an
// error if the length of the given validator-data is less than 32 bytes or the validator-data can not
// be decoded.
func ExtractUconValidators(h *types.Header, backType params.LookBackType) (*UconValidators, error) {
	var data []byte
	if backType == params.LookBackCert {
		data = h.Certificate
	} else {
		data = h.Validator
	}

	var uconVal *UconValidators
	err := rlp.DecodeBytes(data[:], &uconVal)
	if err != nil {
		return nil, err
	}
	return uconVal, nil
}

//CheckValidatorVotes Check voting
func (s *Server) CheckValidatorVotes(chain consensus.ChainReader, header *types.Header) (map[common.Address]bool, error) {
	var requiredValidators = make(map[common.Address]bool)
	yp, err := chain.VersionForRound(header.Number.Uint64())
	if err != nil {
		logging.Error("get YOUChain parameters failed", "round", header.Number, "err", err)
		return requiredValidators, err
	}
	lookBack := s.GetLookBackBlockNumber(&yp.CaravelParams, header.Number, params.LookBackStake)
	lookBackHeader := chain.GetHeaderByNumber(lookBack.Uint64())
	if lookBackHeader == nil {
		logging.Error("lookBackHeader not found.", "lookBack blockNumber", lookBack.String())
		return requiredValidators, fmt.Errorf("header not found")
	}
	vldReader, err := chain.GetVldReader(lookBackHeader.ValRoot)
	if err != nil {
		logging.Error("extract validator failed", "number", header.Number, "err", err, "val", hexutil.Encode(header.Validator))
		return requiredValidators, err
	}
	threshold := yp.ValidatorThreshold
	lbStakeStat, err := vldReader.GetValidatorsStat()
	if err != nil {
		logging.Error("extract no validators lbStakeStat load failed", "height", header.Number)
		return requiredValidators, err
	}

	lbTotalStake := lbStakeStat.GetByKind(params.KindHouse).GetOnlineStake().Uint64()
	if lbTotalStake < threshold || lbTotalStake <= 0 {
		logging.Error("extract no validators", "height", header.Number, "lbTotalStake", lbTotalStake, "threshold", threshold)
		return requiredValidators, err
	}

	lbValidators := vldReader.GetValidators()
	if lbValidators.Len() == 0 {
		logging.Error("extract no validators", "height", header.Number)
		return requiredValidators, err
	}

	stakeToSub := make(map[common.Address]string)
	//todo 投票概率的计算需要重新考虑 来个公式 总抵押、节点抵押、轮数
	for _, v := range lbValidators.List() {
		if v.IsInvalid() || v.Status == params.ValidatorOffline || v.Role != params.RoleHouse {
			continue
		}
		subUsers := (v.Stake.Uint64() * threshold) / lbTotalStake
		if subUsers > 0 {
			requiredValidators[v.MainAddress()] = true
			stakeToSub[v.MainAddress()] = fmt.Sprintf("%d:%d", v.Stake.Uint64(), subUsers)
		}
	}

	if len(requiredValidators) == 0 {
		logging.Error("extract validator failed", "height", header.Number, "err", "no validate validators", "validators", lbValidators.Len())
		return requiredValidators, err
	}
	// verify votes' information
	ucValidators, err := ExtractUconValidators(header, params.LookBackStake)
	if err != nil {
		logging.Error("extract validator failed", "height", header.Number, "err", err, "val", hexutil.Encode(header.Validator))
		return requiredValidators, err
	}

	// export votes of house validators
	activeValidators := make(map[common.Address]uint32)
	payload := append(header.Hash().Bytes(), append(header.Number.Bytes(), uint32ToBytes(ucValidators.RoundIndex)...)...)
	enableBls := yp.EnableBls
	for _, vote := range ucValidators.HouseCommitters {
		var (
			pubKey *ecdsa.PublicKey
			err    error
		)
		if enableBls {
			// extract public key and validator from BLS-Signature
			_, _, pubKey, err = s.blsVerifier.RecoverSignerInfo(lbValidators, &vote)
		} else {
			// extract public key from Signature
			pubKey, err = GetSignaturePublicKey(payload, vote.Signature)
		}
		if err != nil {
			logging.Error("VerifyHeader UconValidators failed. get signature public key failed.", err)
			continue
		}
		if pubKey != nil {
			addr := crypto.PubkeyToAddress(*pubKey)
			activeValidators[addr] = vote.Votes
		}
	}

	inactiveCount := 0
	output := []string{}
	addrs := []common.Address{}
	for addr := range requiredValidators {
		addrs = append(addrs, addr)
	}
	sortedAddresses := common.SortedAddresses(addrs)
	sort.Sort(sortedAddresses)
	for _, addr := range sortedAddresses {
		actual, ok := activeValidators[addr]
		requiredValidators[addr] = ok
		if !ok {
			inactiveCount++
		}
		requiredVotesTip := stakeToSub[addr]
		output = append(output, fmt.Sprintf("%s:%s:%d", addr.String(), requiredVotesTip, actual))
	}
	stakeToSub = nil
	logging.Info("staking extract votes", "height", header.Number.Uint64(), "lbTotal", lbTotalStake, "threshold", threshold, "req", len(requiredValidators), "bad", inactiveCount, "data"+header.Number.String(), strings.Join(output, ","))
	return requiredValidators, nil
}

func (s *Server) GetValidatorAddrs(chain consensus.ChainReader, header *types.Header) (*params.YouParams, *UconValidators, []common.Address, []common.Address, error) {
	yp, err := chain.VersionForRound(header.Number.Uint64())
	if err != nil {
		logging.Error("get YOUChain parameters failed", "round", header.Number, "err", err)
		return nil, nil, nil, nil, err
	}

	var lbValidators *state.Validators
	if yp.EnableBls {
		lookBack := s.GetLookBackBlockNumber(&yp.CaravelParams, header.Number, params.LookBackStake)
		lookBackHeader := chain.GetHeaderByNumber(lookBack.Uint64())
		if lookBackHeader == nil {
			logging.Error("lookBackHeader not found.", "lookBack blockNumber", lookBack.String())
			return yp, nil, nil, nil, fmt.Errorf("header not found")
		}
		vldReader, err := chain.GetVldReader(lookBackHeader.ValRoot)
		if err != nil {
			logging.Error("GetVldReader failed", "number", header.Number, "err", err, "val", hexutil.Encode(header.Validator))
			return yp, nil, nil, nil, err
		}
		lbValidators = vldReader.GetValidators()
	}

	// verify votes' information
	ucValidators, err := ExtractUconValidators(header, params.LookBackStake)
	if err != nil {
		logging.Error("ExtractUconValidators failed", "height", header.Number, "err", err, "val", hexutil.Encode(header.Validator))
		return yp, nil, nil, nil, err
	}

	// export votes
	payload := append(header.Hash().Bytes(), append(header.Number.Bytes(), uint32ToBytes(ucValidators.RoundIndex)...)...)

	getAddrsFn := func(votes []SingleVote) []common.Address {
		addrs := []common.Address{}
		for _, vote := range votes {
			var (
				pubKey *ecdsa.PublicKey
				err    error
			)
			if yp.EnableBls {
				// extract public key and validator from BLS-Signature
				_, _, pubKey, err = s.blsVerifier.RecoverSignerInfo(lbValidators, &vote)
			} else {
				// extract public key from Signature
				pubKey, err = GetSignaturePublicKey(payload, vote.Signature)
			}
			if err != nil {
				logging.Error("GetValidatorAddrs failed.", "err", err)
				continue
			}
			if pubKey != nil {
				addr := crypto.PubkeyToAddress(*pubKey)
				addrs = append(addrs, addr)
			}
		}
		return addrs
	}

	chamberAddrs := getAddrsFn(ucValidators.ChamberCommitters)
	houseAddrs := getAddrsFn(ucValidators.HouseCommitters)

	return yp, ucValidators, chamberAddrs, houseAddrs, nil
}
