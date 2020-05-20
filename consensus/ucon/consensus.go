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
	"fmt"
	"math/big"
	"time"

	"github.com/youchainhq/go-youchain/bls"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
)

var (
	// errUnknownBlock is returned when the list of validators is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")
	// errInvalidMixDigest is returned if a block's mix digest is not digest.
	errInvalidMixDigest = errors.New("invalid mix digest")
	// errInvalidConsensusDataFormat is returned when the consensus data format is incorrect
	errInvalidConsensusDataFormat = errors.New("invalid consensus data format")
	// errInvalidParent is returned if can't get consensus data from a block's parent
	errInvalidParent = errors.New("invalid parent")
	// errInvalidConsensusData is returned if can't get consensus data from a block
	errInvalidConsensusData = errors.New("invalid consensus data")
	// errInvalidSealer is returned if modified block is received
	errInvalidSealer = errors.New("invalid sealer")
)

var (
	allowedFutureBlockTime = 15 * time.Second // Max time from current time allowed for blocks, before they're considered future blocks
)

func (s *Server) Author(header *types.Header) (common.Address, error) {
	return common.Address{}, nil
}

// VerifyHeader checks whether a header confirms to the consensus rules of a
// given engine. Verifying the seal may be done optionally here, or explicitly
// via the VerifySeal method.
func (s *Server) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return s.verifyHeader(chain, header, nil, seal)
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (s *Server) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header, seal bool) error {
	if header.Number == nil {
		return errUnknownBlock
	}

	// Don't waste time checking blocks from the future
	if header.Time > uint64(time.Now().Add(allowedFutureBlockTime).Unix()) {
		return consensus.ErrFutureBlock
	}

	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != types.UConMixHash {
		return errInvalidMixDigest
	}

	//verify sig before massive work
	if err := s.verifySignature(header); err != nil {
		return err
	}

	return s.verifyCascadingFields(chain, header, parents, seal)
}

func (s *Server) verifySignature(header *types.Header) error {
	// Ensure that the consensus data is satisfied
	consensusData, err := ExtractConsensusData(header)
	if err != nil {
		return errInvalidConsensusDataFormat
	}

	consensusPub, err := consensusData.GetPublicKey()
	if err != nil {
		return errInvalidConsensusData
	}

	//todo cal twice
	sigPub, err := crypto.SigToPub(header.Hash().Bytes(), header.Signature)
	if sigPub == nil || crypto.PubkeyToAddress(*consensusPub) != crypto.PubkeyToAddress(*sigPub) {
		return errInvalidSealer
	}

	return nil
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (s *Server) verifyCascadingFields(chain consensus.ChainReader, header *types.Header, parents []*types.Header, seal bool) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// Ensure that the block's timestamp isn't too close to it's parent
	var parentHeader *types.Header
	if len(parents) > 0 {
		parentHeader = parents[len(parents)-1]
	} else {
		parentHeader = chain.GetHeader(header.ParentHash, number-1)
	}

	if parentHeader == nil || parentHeader.Number.Uint64() != number-1 || parentHeader.Hash() != header.ParentHash {
		logging.Warn("try to get parent failed", "header hash", header.Hash().String(), "header number", header.Number,
			"parent hash ", header.ParentHash.String(), "parent number", number-1, "parents", len(parents), "isNil", parentHeader == nil)
		return consensus.ErrUnknownAncestor
	}

	local := chain.GetHeaderByNumber(header.Number.Uint64())
	if local != nil && header.Hash() != local.Hash() {
		logging.Error("Exist canonical", "localHash", local.Hash().String(), "headerHash", header.Hash().String())
		return consensus.ErrExistCanonical
	}
	if seal {
		return s.verifyConsensusField(chain, header, parents)
	}
	return nil
}

func (s *Server) verifyConsensusField(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {

	yp, err := chain.VersionForRoundWithParents(header.Number.Uint64(), parents)
	if err != nil {
		return err
	}
	cp := &yp.CaravelParams
	seedHeader, err := s.getLookBackHeader(cp, chain, header.Number, params.LookBackSeed, parents)
	if err != nil {
		return consensus.ErrUnknownAncestor
	}
	vldReader, err := s.getLookBackValReader(cp, chain, header.Number, params.LookBackStake, parents)
	if err != nil {
		return consensus.ErrUnknownLookBackValidators
	}

	var certSeedHeader *types.Header
	var certVldReader state.ValidatorReader
	if header.Number.Uint64() > 0 && header.Number.Uint64()%params.ACoCHTFrequency == 0 {
		certSeedHeader, err = s.getLookBackHeader(nil, chain, header.Number, params.LookBackCertSeed, parents)
		if err != nil {
			return consensus.ErrUnknownAncestor
		}
		certVldReader, err = s.getLookBackValReader(nil, chain, header.Number, params.LookBackCertStake, parents)
		if err != nil {
			// Note: here we do not return the consensus.ErrUnknownParentState,
			// because it should not be handled specifically by the caller when this happened.
			return err
		}
	}
	return s.verifyConsensusFieldMain(cp, seedHeader, vldReader, certSeedHeader, certVldReader, header)
}

func (s *Server) getLookBackHeader(cp *params.CaravelParams, chain consensus.ChainReader, currNum *big.Int, lbtype params.LookBackType, parents []*types.Header) (*types.Header, error) {
	var lookBackHeader *types.Header
	lookBack := s.GetLookBackBlockNumber(cp, currNum, lbtype)
	minLen := int(big.NewInt(0).Sub(currNum, lookBack).Int64())
	if len(parents) >= minLen {
		lookBackHeader = parents[len(parents)-minLen]
		//logging.Info("VerifyHeader get lookBack from parents' list.", "Height", lookBackHeader.Number)
	} else {
		lookBackHeader = chain.GetHeaderByNumber(lookBack.Uint64())
	}

	if lookBackHeader == nil {
		logging.Error("VerifyHeader failed. Look back block doesn't exist.", "Height", currNum, "LookBack", lookBack, "parents", len(parents))
		return nil, consensus.ErrUnknownAncestor
	}
	logging.Debug("VerifyConsensusField", "root", lookBackHeader.Root.String(), "hn", currNum, "ln", lookBackHeader.Number)
	return lookBackHeader, nil
}

func (s *Server) getLookBackValReader(cp *params.CaravelParams, chain consensus.ChainReader, currNum *big.Int, lbtype params.LookBackType, parents []*types.Header) (state.ValidatorReader, error) {
	lbHeader, err := s.getLookBackHeader(cp, chain, currNum, lbtype, parents)
	var reader state.ValidatorReader
	if err == nil {
		reader, err = chain.GetVldReader(lbHeader.ValRoot)
		if err != nil {
			logging.Error("Can not get look back validator reader", "currNum", currNum, "lbNum", lbHeader.Number, "err", err)
		}
	}
	return reader, err
}

func (s *Server) verifyConsensusFieldMain(cp *params.CaravelParams, seedHeader *types.Header, vldReader state.ValidatorReader, certHeader *types.Header, certVldReader state.ValidatorReader, header *types.Header) error {
	verifyProc := time.Now()

	seedCon, err := GetConsensusDataFromHeader(seedHeader)
	if err != nil {
		logging.Error("Can not get look back consensus", "lookBack", seedHeader.Number, "err", err)
		return errors.New("can not get look back consensus")
	}

	consensusData, err := GetConsensusDataFromHeader(header)
	if err != nil {
		logging.Error("VerifyHeader failed. Get consensus data failed.", err)
		return errInvalidConsensusData
	}
	// get block proposer's public key and VRF public key
	pubKey, err := consensusData.GetPublicKey()
	if err != nil {
		logging.Error("VerifyHeader failed. Get public key failed.", err)
		return errInvalidConsensusData
	}
	vrfPK, err := secp256k1VRF.NewVRFVerifier(pubKey)
	if err != nil {
		logging.Error("VerifyHeader failed. Get VRF public key failed.", err)
		return errInvalidConsensusData
	}

	// verify priority, also do sortition verification
	addr := crypto.PubkeyToAddress(*pubKey)
	validator := vldReader.GetValidatorByMainAddr(addr)
	if validator == nil {
		logging.Error("VerifyHeader failed")
		return errors.New("illegal proposer")
	}
	vs, err := vldReader.GetValidatorsStat()
	if err != nil {
		return err
	}
	isValid, err := VrfVerifyPriority(vrfPK, seedCon.Seed, consensusData.RoundIndex, UConStepProposal, consensusData.SortitionProof,
		consensusData.Priority, consensusData.SubUsers, consensusData.ProposerThreshold, validator.Stake, vs.GetStakeByKind(params.KindChamber))
	if err != nil || !isValid {
		logging.Error("VerifyHeader failed, priority is invalid.", "Round", consensusData.Round, "RoundIndex", consensusData.RoundIndex,
			"hash", header.Hash().String(), "parent", header.ParentHash.String(), "stake", validator.Stake, "totalStake", vs.GetStakeByKind(params.KindChamber), "err", err)
		return errInvalidConsensusData
	}
	logging.Info("VerifyHeader priority Process.", "Round", consensusData.Round, "RoundIndex", consensusData.RoundIndex, " using: ", time.Now().Sub(verifyProc))
	verifyProc = time.Now()

	// verify votes' information
	ucValidators, err := ExtractUconValidators(header, params.LookBackPos)
	if err != nil {
		logging.Error("VerifyHeader failed. Get UconValidators failed.", "Round", consensusData.Round, "RoundIndex", consensusData.RoundIndex, "err", err)
		return errInvalidConsensusData
	}

	cd := &commonData{
		cp:                 cp,
		lbVld:              vldReader,
		headerHash:         header.Hash().Bytes(),
		seed:               seedCon.Seed,
		round:              consensusData.Round,
		roundIndex:         ucValidators.RoundIndex,
		validatorThreshold: consensusData.ValidatorThreshold,
	}
	err = s.verifyVotes(cd, ucValidators.ChamberCommitters, ucValidators.SCAggrSig, uint32(Precommit), params.KindChamber, true)
	if err != nil {
		return err
	}

	//if vs.GetCountOfKind(params.KindHouse) > 0 {
	//	err = s.verifyVotes(cd, ucValidators.HouseCommitters, ucValidators.MCAggrSig, uint32(Precommit), params.KindHouse, true)
	//	if err != nil {
	//		return err
	//	}
	//}

	// verify Certificate
	if header.Number.Uint64() > 0 && header.Number.Uint64()%params.ACoCHTFrequency == 0 {

		certCon, err := GetConsensusDataFromHeader(certHeader)
		if err != nil {
			logging.Error("Can not get look back consensus", "lookBack", certHeader.Number, "err", err)
			return errors.New("can not get look back consensus")
		}

		//SPECIAL: switch to using a protocol version recorded on certHeader
		yp, ok := params.Versions[certHeader.CurrVersion]
		if !ok {
			return fmt.Errorf("YOUChain version of \"%d\" not exists, headerNumber: %d", certHeader.CurrVersion, certHeader.Number.Uint64())
		}
		cd.cp = &yp.CaravelParams
		cd.lbVld = certVldReader
		cd.seed = certCon.Seed
		cd.validatorThreshold = certCon.CertValThreshold
		ucCertificates, err := ExtractUconValidators(header, params.LookBackCert)
		if err != nil {
			logging.Error("VerifyHeader failed. Get ucCertificates from Look back block failed.", "Round", consensusData.Round, "RoundIndex", consensusData.RoundIndex, err)
			return errInvalidConsensusData
		}
		err = s.verifyVotes(cd, ucCertificates.ChamberCerts, ucCertificates.CCAggrSig, uint32(Certificate), params.KindChamber, false)
		if err != nil {
			return err
		}
	}

	logging.Info("VerifyHeader UconValidators.", "Round", consensusData.Round, "RoundIndex", ucValidators.RoundIndex, "Size", len(header.Validator[:]), " using: ", time.Now().Sub(verifyProc))

	return err
}

type commonData struct {
	cp                 *params.CaravelParams
	lbVld              state.ValidatorReader
	headerHash         []byte
	seed               common.Hash
	round              *big.Int
	roundIndex         uint32
	validatorThreshold uint64
}

//func verifyCommonVotes(cd *commonData, validators []SingleVote, step uint32, kind params.ValidatorKind, isPos bool) error {
//	count := uint32(0)
//	threshold := cd.validatorThreshold //uint64(float64(totalStake.Uint64()) * ValidatorProportionFloat(cd.validatorProportion))
//	vstate, err := cd.lbState.GetValidatorsStat()
//	if err != nil {
//		logging.Info("VerifyHeader failed.", "Round", cd.round, "RoundIndex", cd.roundIndex)
//		return err
//	}
//	totalStake := vstate.GetStakeByKind(kind)
//	payload := append(cd.headerHash, append(cd.round.Bytes(), int32ToBytes(cd.roundIndex)...)...) ////append(blockHash.Bytes(), int32ToBytes(vote.Votes)...)
//	for _, vote := range validators {
//		// extract public key from Signature
//		pubKey, err := GetSignaturePublicKey(payload, vote.Signature)
//		if err != nil {
//			logging.Error("VerifyHeader UconValidators failed. get signature public key failed.", err)
//			continue
//		}
//
//		pk, err := secp256k1VRF.NewVRFVerifier(pubKey)
//		if err != nil {
//			logging.Error("VerifyHeader UconValidators failed. get pubKey failed: ", err)
//			continue
//		}
//
//		addr := crypto.PubkeyToAddress(*pubKey)
//		validator := cd.lbState.GetValidatorByMainAddr(addr)
//
//		// verify sortition
//		isValid, err := VrfVerifySortition(pk, cd.seed, cd.roundIndex, step, vote.Proof, threshold, validator.Stake, totalStake)
//		if err != nil || !isValid {
//			logging.Error("VerifyHeader UconValidators failed.", "Round", cd.round, "RoundIndex", cd.roundIndex,
//				"Sub-Users", vote.Votes, "step", step, "validatorTh", threshold,
//				"stake", validator.Stake, "totalStake", totalStake, "seed", cd.seed.String(), "addr", addr.String(),
//				"err", err)
//			continue
//		}
//		count += vote.Votes
//	}
//	if !OverThreshold(count, threshold, isPos) {
//		logging.Error("VerifyHeader UconValidators failed. Not enough validators.",
//			"Round", cd.round, "RoundIndex", cd.roundIndex, "Step", step, "Kind", kind,
//			"Threshold", threshold, "Validators", count, "TotalStake", totalStake)
//		return errInvalidConsensusData
//	}
//	return nil
//}

func (s *Server) verifyVotes(cd *commonData, votes []SingleVote, asig []byte, step uint32, kind params.ValidatorKind, isPos bool) error {
	start := time.Now()
	var sig bls.Signature
	if cd.cp.EnableBls {
		defer func() {
			logging.Debug("verifyBlsVotes", "time", time.Now().Sub(start).String())
		}()

		var err error
		sig, err = s.blsMgr.DecSignature(asig)
		if err != nil {
			return fmt.Errorf("invalid aggregated signatue: %v", err)
		}
	}
	blspubs := make([]bls.PublicKey, 0, len(votes))

	count := uint32(0)
	threshold := cd.validatorThreshold //uint64(float64(totalStake.Uint64()) * ValidatorProportionFloat(cd.validatorProportion))
	vstate, err := cd.lbVld.GetValidatorsStat()
	if err != nil {
		logging.Info("VerifyHeader failed.", "Round", cd.round, "RoundIndex", cd.roundIndex)
		return err
	}
	totalStake := vstate.GetStakeByKind(kind)
	payload := append(cd.headerHash, append(cd.round.Bytes(), uint32ToBytes(cd.roundIndex)...)...)
	vs := cd.lbVld.GetValidators()
	staData := make(map[common.Address]bool)
	for _, v := range votes {
		var validator *state.Validator
		var pubKey *ecdsa.PublicKey
		var addr common.Address
		if cd.cp.EnableBls {
			// extract public key and validator from BLS-Signature
			var pk bls.PublicKey
			validator, pk, pubKey, err = s.blsVerifier.RecoverSignerInfo(vs, &v)
			if err != nil {
				logging.Error("RecoverSignerInfo failed, validators", "vStat", vstate)
				return fmt.Errorf("verifyBlsVotes can't recover signer info, error: %v", err)
			}
			addr = crypto.PubkeyToAddress(*pubKey)
			if staData[addr] == true {
				continue
			} else {
				blspubs = append(blspubs, pk)
			}
		} else {
			// extract public key from Signature
			pubKey, err = GetSignaturePublicKey(payload, v.Signature)
			if err != nil {
				logging.Error("VerifyHeader UconValidators failed. get signature public key failed.", err)
				continue
			}

			addr = crypto.PubkeyToAddress(*pubKey)
			validator = cd.lbVld.GetValidatorByMainAddr(addr)
		}
		if staData[addr] == true {
			continue
		}

		//verify sortition
		vrfpk, err := secp256k1VRF.NewVRFVerifier(pubKey)
		if err != nil {
			logging.Error("VerifyHeader UconValidators failed. get pubKey failed: ", err)
			continue
		}
		isValid, err := VrfVerifySortition(vrfpk, cd.seed, cd.roundIndex, step, v.Proof, v.Votes, threshold, validator.Stake, totalStake)
		if err != nil || !isValid {
			logging.Error("VerifyHeader UconValidators failed.", "Round", cd.round, "RoundIndex", cd.roundIndex,
				"Sub-Users", v.Votes, "step", step, "validatorTh", threshold,
				"stake", validator.Stake, "totalStake", totalStake, "seed", cd.seed.String(), "varaddr", validator.MainAddress().String(),
				"err", err)
			continue
		}
		staData[addr] = true
		count += v.Votes
	}
	if !OverThreshold(count, threshold, isPos) {
		logging.Error("VerifyHeader UconValidators failed. Not enough validators.",
			"Round", cd.round, "RoundIndex", cd.roundIndex, "Step", step, "Kind", kind,
			"Threshold", threshold, "Validators", count, "TotalStake", totalStake)
		return errInvalidConsensusData
	}

	if cd.cp.EnableBls {
		logging.Debug("verifyBlsVotes before VerifyAggregatedN", "using", time.Now().Sub(start).String())
		err = s.blsMgr.VerifyAggregatedOne(blspubs, payload, sig)
		if err != nil {
			logging.Error("VerifyHeader UconValidators failed. VerifyAggregatedOne",
				"Round", cd.round, "RoundIndex", cd.roundIndex, "Step", step, "Kind", kind,
				"Threshold", threshold, "Validators", count, "TotalStake", totalStake)
		}
		return err
	}
	return nil
}

//func (s *Server) verifyBlsCommonVotes(cd *commonData, votes []SingleVote, step uint32, kind params.ValidatorKind, asig []byte, isPos bool) error {
//	start := time.Now()
//	defer func() {
//		logging.Debug("verifyBlsVotes", "time", time.Now().Sub(start).String())
//	}()
//	sig, err := s.blsMgr.DecSignature(asig)
//	if err != nil {
//		return fmt.Errorf("invalid aggregated signatue: %v", err)
//	}
//	count := uint32(0)
//	threshold := cd.validatorThreshold //uint64(float64(totalStake.Uint64()) * ValidatorProportionFloat(cd.validatorProportion))
//	vstate, err := cd.lbState.GetValidatorsStat()
//	if err != nil {
//		logging.Info("VerifyHeader failed.", "Round", cd.round, "RoundIndex", cd.roundIndex)
//		return err
//	}
//	totalStake := vstate.GetStakeByKind(kind)
//	blspubs := make([]bls.PublicKey, 0, len(votes))
//	payload := append(cd.headerHash, append(cd.round.Bytes(), int32ToBytes(cd.roundIndex)...)...)
//	vs := cd.lbState.GetValidators()
//	for _, v := range votes {
//		signer, pk, vrfrawPk, err := s.blsVerifier.RecoverSignerInfo(vs, &v)
//		if err != nil {
//			logging.Error("RecoverSignerInfo failed, validators", "vStat", vstate)
//			return fmt.Errorf("verifyBlsVotes can't recover signer info, error: %v", err)
//		}
//
//		//verify sortition
//		vrfpk, err := secp256k1VRF.NewVRFVerifier(vrfrawPk)
//		if err != nil {
//			logging.Error("VerifyHeader UconValidators failed. get pubKey failed: ", err)
//			continue
//		}
//		isValid, err := VrfVerifySortition(vrfpk, cd.seed, cd.roundIndex, step, v.Proof, threshold, signer.Stake, totalStake)
//		if err != nil || !isValid {
//			logging.Error("VerifyHeader UconValidators failed.", "Round", cd.round, "RoundIndex", cd.roundIndex,
//				"Sub-Users", v.Votes, "step", step, "validatorTh", threshold,
//				"stake", signer.Stake, "totalStake", totalStake, "seed", cd.seed.String(), "id", signer.Identify,
//				"err", err)
//			continue
//		}
//		count += v.Votes
//
//		blspubs = append(blspubs, pk)
//	}
//	if !OverThreshold(count, threshold, isPos) {
//		logging.Error("VerifyHeader UconValidators failed. Not enough validators.",
//			"Round", cd.round, "RoundIndex", cd.roundIndex, "Step", step, "Kind", kind,
//			"Threshold", threshold, "Validators", count, "TotalStake", totalStake)
//		return errInvalidConsensusData
//	}
//	logging.Debug("verifyBlsVotes before VerifyAggregatedN", "using", time.Now().Sub(start).String())
//	err = s.blsMgr.VerifyAggregatedOne(blspubs, payload, sig)
//	if err != nil {
//		logging.Error("VerifyHeader UconValidators failed. VerifyAggregatedOne",
//			"Round", cd.round, "RoundIndex", cd.roundIndex, "Step", step, "Kind", kind,
//			"Threshold", threshold, "Validators", count, "TotalStake", totalStake)
//	}
//	return err
//}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications (the order is that of
// the input slice).
func (s *Server) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{}, 1)
	bufLen := len(headers)
	// Concurrency control, because this control is a post-action control,
	// so it must leave 2 slots, one for the in-flight verifying header,
	// and the other for the processing but not written block.
	//
	// Also, we should believe that the StakeLookBack should be greater then 2,
	// so we did not check a negative number in here.
	if bufLen > params.MinStakeLookBack()-2 {
		bufLen = params.MinStakeLookBack() - 2
	}
	results := make(chan error, bufLen)
	go func() {
		for i, header := range headers {
			err := s.verifyHeader(chain, header, headers[:i], seals[i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// VerifySeal checks whether the crypto seal on a header is valid according to
// the consensus rules of the given engine.
func (s *Server) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	logging.Debug("VerifySeal", "number", header.Number)

	if err := s.verifySignature(header); err != nil {
		return err
	}
	return s.verifyConsensusField(chain, header, nil)
}

// VerifySideChainHeader checks whether a side chain block confirms to the consensus rules
func (s *Server) VerifySideChainHeader(cp *params.CaravelParams, seedHeader *types.Header, vldReader state.ValidatorReader, certHeader *types.Header, certVldReader state.ValidatorReader, block *types.Block, parents []*types.Block) error {
	logging.Debug("VerifySideChainHeader", "number", block.Number())
	//verify cascading
	l := len(parents)
	if l <= 0 {
		return errors.New("no parents")
	}
	parentHeader := parents[l-1].Header()
	header := block.Header()
	if header.Number == nil {
		return errUnknownBlock
	}
	numDiff := new(big.Int).Sub(header.Number, parentHeader.Number)
	if !numDiff.IsInt64() || numDiff.Int64() != 1 || header.ParentHash != parentHeader.Hash() {
		logging.Warn("VerifySideChainHeader unknown ancestor: number ", block.Number(), "parentNumber ", parentHeader.Number, "header.ParentHash ", header.ParentHash.String(), "parenthash ", parentHeader.Hash().String())
		return consensus.ErrUnknownAncestor
	}

	//verifyConsensusField
	return s.verifyConsensusFieldMain(cp, seedHeader, vldReader, certHeader, certVldReader, block.Header())
}

func findHeaderFromTrustedParents(number *big.Int, parents []*types.Header) *types.Header {
	var result *types.Header
	vpLen := len(parents)
	for i := vpLen - 1; i >= 0; i-- {
		if number.Cmp(parents[i].Number) == 0 {
			result = parents[i]
		}
	}
	return result
}

// VerifyAcHeader verifies the header using and only using cht certificates
func (s *Server) VerifyAcHeader(chain consensus.ChainReader, acHeader *types.Header, verifiedAcParents []*types.Header) error {
	if nil == acHeader || len(acHeader.ChtRoot) == 0 {
		return errors.New("no chtRoot in the header")
	}
	num := acHeader.Number.Uint64()
	if num%params.ACoCHTFrequency != 0 {
		return fmt.Errorf("header %d is not a acHeader", num)
	}
	// extract current consensus data and cht certs
	chtCerts, err := ExtractUconValidators(acHeader, params.LookBackCert)
	if err != nil {
		return err
	}
	currConsData, err := ExtractConsensusData(acHeader)
	if err != nil {
		return fmt.Errorf("can't extract sonsensus data from current header: %v", err)
	}
	// get seed header and stake header
	seedLookBack := s.GetLookBackBlockNumber(nil, acHeader.Number, params.LookBackCertSeed)
	seedHeader := chain.GetHeaderByNumber(seedLookBack.Uint64())
	stakeLookBack := s.GetLookBackBlockNumber(nil, acHeader.Number, params.LookBackCertStake)
	stakeHeader := chain.GetHeaderByNumber(stakeLookBack.Uint64())
	if seedHeader == nil {
		// try find from verified parents
		seedHeader = findHeaderFromTrustedParents(seedLookBack, verifiedAcParents)
	}
	if stakeHeader == nil {
		stakeHeader = findHeaderFromTrustedParents(stakeLookBack, verifiedAcParents)
	}
	if nil == seedHeader || nil == stakeHeader {
		return errors.New("can not find look-back header")
	}

	//SPECIAL: using a protocol version recorded on seedHeader
	yp, ok := params.Versions[seedHeader.CurrVersion]
	if !ok {
		return fmt.Errorf("YOUChain version of \"%d\" not exists, headerNumber: %d", seedHeader.CurrVersion, seedHeader.Number.Uint64())
	}

	// extract consensus data from seed header
	seedConsData, err := ExtractConsensusData(seedHeader)
	if err != nil {
		return fmt.Errorf("can't extract sonsensus data from seed header: %v", err)
	}
	// get validator reader at stake header
	vldReader, err := chain.GetVldReader(stakeHeader.ValRoot)
	if err != nil {
		logging.Debug("can not get the look back validators reader", "currNum", num, "stakeLookBackNum", stakeLookBack.Uint64(), "lookBackValRoot", stakeHeader.ValRoot.String())
		return fmt.Errorf("can not get the look back validators reader: %v", err)
	}
	// verify cht certificates
	cd := &commonData{
		cp:                 &yp.CaravelParams,
		lbVld:              vldReader,
		headerHash:         acHeader.Hash().Bytes(),
		seed:               seedConsData.Seed,
		round:              currConsData.Round,
		roundIndex:         chtCerts.RoundIndex,
		validatorThreshold: seedConsData.CertValThreshold,
	}
	err = s.verifyVotes(cd, chtCerts.ChamberCerts, chtCerts.CCAggrSig, uint32(Certificate), params.KindChamber, false)
	if err != nil {
		return fmt.Errorf("verify cht certificates failed: %v", err)
	}
	return nil
}

func (s *Server) UpdateContextForNewBlock(block *types.Block) error {
	if s.isMining() {
		s.StartNewRound(true)
	}
	return nil
}

// Seal generates a new block for the given input block with the local miner's
// seal place on top.
func (s *Server) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	header := block.Header()
	_, err := GetConsensusDataFromHeader(header)
	logging.Info("Seal.", "Round", block.Number(), "Hash", block.Hash().String())
	if err != nil {
		logging.Error("Seal failed.", "Height", block.Number())
		return nil, fmt.Errorf("Seal failed. Height: %d", block.Number())
	}

	//append signature
	sig, err := crypto.Sign(header.Hash().Bytes(), s.rawSk)
	if err != nil {
		logging.Error("Seal sig failed", "Height:", header.Number.Uint64())
		return nil, err
	}
	header.Signature = sig
	block = block.WithSeal(header)

	s.eventMux.AsyncPost(BlockProposalEvent{Block: block})

	return nil, nil
}

func (s *Server) Prepare(chain consensus.ChainReader, header *types.Header) error {
	if !s.isMining() {
		return fmt.Errorf("not called start")
	}

	// copy the parent extra data as the header extra data
	number := header.Number.Uint64()
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		logging.Error("find parent failed", "parenthash", header.ParentHash.String(), "parentheight", number-1)
		return consensus.ErrUnknownAncestor
	}

	//round, roundIndex := s.getRoundAndIndex()
	preConsensus, err := GetConsensusDataFromHeader(parent)
	if err != nil {
		logging.Error("Prepare failed.", "Height", number)
		return fmt.Errorf("Prepare failed. Height: %d", number)
	}
	round := big.NewInt(preConsensus.Round.Int64() + 1)
	roundIndex := uint32(1)
	if round.Cmp(s.currentRound) == 0 {
		roundIndex = s.roundIndex
	}
	logging.Info("Prepare.", "Round", round, "RoundIndex", roundIndex, "Height", number)
	if number != round.Uint64() {
		logging.Error("error: Height and Round don't match.", "Height", number, "Round", round)
	}

	// check whether is the proposer. if not, return error; else propose block and start new round
	isRole, stepView := s.sortitionMgr.isProposer(round, roundIndex)
	if isRole {
		//stepView := s.sortitionMgr.GetStepView(round, roundIndex, UConStepProposal) //s.getStepView(UConStepProposal)
		if stepView == nil {
			logging.Error("StepView empty.", "Round", round, "RoundIndex", roundIndex)
			return fmt.Errorf("StepView empty. Round: %d RoundIndex: %d", round, roundIndex)
		}
		// construct consensus data which should be added to the header of the proposed block
		cp := s.CurrentCaravelParams()
		consensusData := BlockConsensusData{
			Round:              round,
			RoundIndex:         roundIndex,
			Seed:               stepView.SeedValue,
			SortitionProof:     stepView.SortitionProof,
			Priority:           stepView.Priority,
			SubUsers:           stepView.SubUsers,
			ProposerThreshold:  cp.ProposerThreshold,
			ValidatorThreshold: cp.ValidatorThreshold,
			CertValThreshold:   cp.CertValThreshold,
		}
		err := consensusData.SetSignature(s.rawSk)
		if err != nil {
			logging.Error("SetSignature failed", "err", err)
			return fmt.Errorf("SetSignature failed: %x", err)
		}

		// assemble consensus data and header
		consensusBytes, err := PrepareConsensusData(header, &consensusData)
		if err != nil {
			return err
		}

		header.Consensus = consensusBytes
		header.MixDigest = types.UConMixHash

		return nil
	}

	return fmt.Errorf("not a proposer")
}

func (s *Server) Finalize(chain consensus.ChainReader, header *types.Header, statedb *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt) {
	//reward is not for a single block in ucon, and is not implemented in here.
	// and, we don't re-construct the ACoCHT here, so, do nothing!
}

func (s *Server) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt) (*types.Block, error) {
	header.Root, header.ValRoot, header.StakingRoot = state.IntermediateRoot(true)
	chtRoot, bltRoot, err := chain.GetAcReader().ReadAcNode(header.Number.Uint64(), header.ParentHash)
	if err != nil {
		return nil, err
	}
	header.ChtRoot = chtRoot
	header.BltRoot = bltRoot
	strChtRoot, strBltRoot := "", ""
	if len(chtRoot) > 0 {
		strChtRoot = hexutil.Encode(chtRoot)
		strBltRoot = hexutil.Encode(bltRoot)
	}
	logging.Info("FinalizeAndAssemble.", "Round", s.currentRound, "RoundIndex", s.roundIndex, "Hash", header.Hash().String(), "receipts", len(receipts), "receiptsRoot", types.DeriveSha(types.Receipts(receipts)).String(), "chtRoot", strChtRoot, "bltRoot", strBltRoot)
	return types.NewBlock(header, txs, receipts), nil
}

// fork-selection rules
//   -1 if blockA <  blockB
//    0 if blockA == blockB
//   +1 if blockA >  blockB
//
func (s *Server) CompareBlocks(blockA *types.Block, blockB *types.Block) int {
	if blockA.NumberU64() != blockB.NumberU64() {
		return int(0)
	}

	if blockB.Transactions().Len() == 0 && blockA.Transactions().Len() > 0 {
		return int(1)
	} else if blockA.Transactions().Len() == 0 && blockB.Transactions().Len() > 0 {
		return int(-1)
	}

	consensusA, errA := GetConsensusDataFromHeader(blockA.Header())
	consensusB, errB := GetConsensusDataFromHeader(blockB.Header())
	if errA != nil && errB != nil {
		return int(0)
	}
	if errA == nil && errB != nil {
		return int(1)
	}
	if errA != nil && errB == nil {
		return int(-1)
	}
	if consensusA.RoundIndex > 0 && consensusA.RoundIndex < consensusB.RoundIndex {
		return int(1)
	} else if consensusB.RoundIndex > 0 && consensusA.RoundIndex > consensusB.RoundIndex {
		return int(-1)
	} else {
		return CompareCommonHash(consensusA.Priority, consensusB.Priority)
	}
}
