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

	lru "github.com/hashicorp/golang-lru"
	"github.com/youchainhq/go-youchain/bls"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
)

const blsCacheSize = 2000

type BlsVerifier struct {
	blsMgr bls.BlsManager

	blsPubKeyCache *lru.Cache
	blsSigCache    *lru.Cache
	vrfPkCache     *lru.Cache
}

func NewBlsVerifier(mgr bls.BlsManager) *BlsVerifier {
	v := &BlsVerifier{
		blsMgr: mgr,
	}
	v.blsPubKeyCache, _ = lru.New(blsCacheSize)
	v.blsSigCache, _ = lru.New(blsCacheSize)
	v.vrfPkCache, _ = lru.New(blsCacheSize)
	return v
}

func (v *BlsVerifier) PackVotes(ev CommitEvent, backType params.LookBackType) (*UconValidators, error) {
	uv := &UconValidators{
		RoundIndex: ev.RoundIndex,
	}
	var err error
	if backType == params.LookBackCert {
		uv.ChamberCerts, uv.CCAggrSig, err = v.aggregateVotes(ev.ChamberCerts)
		if err != nil {
			return nil, err
		}
	} else {
		uv.ChamberCommitters, uv.SCAggrSig, err = v.aggregateVotes(ev.ChamberPrecommits)
		if err != nil {
			return nil, err
		}

		uv.HouseCommitters, uv.MCAggrSig, err = v.aggregateVotes(ev.HousePrecommits)
		if err != nil {
			return nil, err
		}
	}

	return uv, nil
}

func (v *BlsVerifier) aggregateVotes(vs VotesInfoForBlockHash) ([]SingleVote, []byte, error) {
	originSigs := make([]bls.Signature, 0, len(vs))
	votes := make([]SingleVote, 0, len(vs))
	for addr, pv := range vs {
		sig, err := v.GetBlsSig(pv.Signature)
		if err != nil {
			err = fmt.Errorf("got an invalid signature. Addr: %s sig: %x, err: %v", addr.String(), pv.Signature, err)
			return nil, nil, err
		}
		originSigs = append(originSigs, sig)
		v := *pv
		v.Signature = nil
		votes = append(votes, v)
	}
	if len(originSigs) > 0 {
		asig, err := v.blsMgr.Aggregate(originSigs)
		if err != nil {
			return nil, nil, err
		}
		return votes, asig.Compress().Bytes(), err
	}
	return votes, []byte{}, nil
}

func (v *BlsVerifier) RecoverSignerInfo(vs *state.Validators, vote *SingleVote) (signer *state.Validator, pk bls.PublicKey, vrfpk *ecdsa.PublicKey, err error) {
	signer, exist := vs.GetByIndex(int(vote.VoterIdx))
	if !exist {
		err = fmt.Errorf("invalid voter index: %d, validators len: %d", vote.VoterIdx, vs.Len())
		return
	}
	pk, err = v.GetBlsPubKey(signer.BlsPubKey)
	if err != nil {
		return
	}
	vrfpk, err = v.GetVrfPubKey(signer.MainPubKey)
	if err != nil {
		return
	}
	return signer, pk, vrfpk, err
}

func (v *BlsVerifier) GetVrfPubKey(bspubKey []byte) (*ecdsa.PublicKey, error) {
	cacheKey := hexutil.Encode(bspubKey)
	if pk, ok := v.vrfPkCache.Get(cacheKey); ok {
		return pk.(*ecdsa.PublicKey), nil
	} else {
		var (
			pk  *ecdsa.PublicKey
			err error
		)
		if len(bspubKey) == 33 {
			pk, err = crypto.DecompressPubkey(bspubKey)
		} else if len(bspubKey) == 65 {
			pk, err = crypto.UnmarshalPubkey(bspubKey)
		} else {
			err = errors.New("invalid length of public key bytes")
		}
		if err != nil {
			return nil, err
		}
		v.vrfPkCache.Add(cacheKey, pk)
		return pk, nil
	}
}

func (v *BlsVerifier) GetBlsPubKey(bspubKey []byte) (bls.PublicKey, error) {
	cacheKey := hexutil.Encode(bspubKey)
	if pk, ok := v.blsPubKeyCache.Get(cacheKey); ok {
		return pk.(bls.PublicKey), nil
	} else {
		pk, err := v.blsMgr.DecPublicKey(bspubKey)
		if err != nil {
			return nil, err
		}
		v.blsPubKeyCache.Add(cacheKey, pk)
		return pk, nil
	}
}

func (v *BlsVerifier) GetBlsSig(sig []byte) (bls.Signature, error) {
	cacheKey := hexutil.Encode(sig)
	if s, ok := v.blsSigCache.Get(cacheKey); ok {
		return s.(bls.Signature), nil
	} else {
		blsSig, err := v.blsMgr.DecSignature(sig)
		if err != nil {
			return nil, err
		}
		v.blsSigCache.Add(cacheKey, blsSig)
		return blsSig, nil
	}
}

func (v *BlsVerifier) AggregateSignatures(rawSigs [][]byte) (aggregatedSig []byte, err error) {
	if len(rawSigs) == 0 {
		err = errors.New("no raw signatures")
		return
	}
	originSigs := make([]bls.Signature, 0, len(rawSigs))
	for _, raw := range rawSigs {
		sig, err := v.GetBlsSig(raw)
		if err != nil {
			err = fmt.Errorf("invalid signature. rawSig: %x, err: %v", raw, err)
			return nil, err
		}
		originSigs = append(originSigs, sig)
	}
	asig, err := v.blsMgr.Aggregate(originSigs)
	if err != nil {
		return nil, err
	}
	return asig.Compress().Bytes(), nil
}

type VoteBLSMgr struct {
	Verifier *BlsVerifier
	rawSk    *ecdsa.PrivateKey
	blsSk    bls.SecretKey
	blsMgr   bls.BlsManager
	myIdx    int //my index in validators
	myAddr   common.Address

	lbMgr LookBackMgr
	lbVld state.ValidatorReader //current look back validator reader

	lbCertVld state.ValidatorReader // current look back certificate validator reader
	myCertIdx int                   // my index in certficate look back validators
	currRound *big.Int
}

func NewVoteBLSMgr(rawSk *ecdsa.PrivateKey, blsSk bls.SecretKey) *VoteBLSMgr {
	vb := &VoteBLSMgr{
		rawSk:  rawSk,
		blsSk:  blsSk,
		blsMgr: bls.NewBlsManager(),
	}
	vb.Verifier = NewBlsVerifier(vb.blsMgr)
	if nil != rawSk {
		vb.myAddr = crypto.PubkeyToAddress(rawSk.PublicKey)
	}

	return vb
}

func (vb *VoteBLSMgr) SetLookBackMgr(lbmgr LookBackMgr) {
	vb.lbMgr = lbmgr
}

func (vb *VoteBLSMgr) update(round *big.Int, isCertRound bool) {

	updateVldFn := func(cp *params.CaravelParams, round *big.Int, lbType params.LookBackType) (state.ValidatorReader, int) {
		vld, err := vb.lbMgr.GetLookBackVldReader(cp, round, lbType)
		if err != nil {
			logging.Crit("VoteBLSMgr update, GetLookBackVldReader failed", "err", err)
		}
		idx, ok := vld.GetValidators().GetIndex(vb.myAddr)
		if !ok {
			idx = -1
		}
		return vld, idx
	}
	vb.lbVld, vb.myIdx = updateVldFn(vb.lbMgr.CurrentCaravelParams(), round, params.LookBackStake)

	if isCertRound {
		vb.lbCertVld, vb.myCertIdx = updateVldFn(nil, round, params.LookBackCertStake)
	} else {
		vb.lbCertVld, vb.myCertIdx = nil, -1
	}
	vb.currRound = new(big.Int).Set(round)
}

func (vb *VoteBLSMgr) SignVote(voteType VoteType, voteInfo *SingleVote, payload []byte) error {
	idx := vb.myIdx
	if voteType == Certificate {
		idx = vb.myCertIdx
	}
	if idx < 0 {
		return errors.New("not in validators set")
	}
	sig := vb.blsSk.Sign(payload)
	voteInfo.VoterIdx = uint32(idx)
	voteInfo.Signature = sig.Compress().Bytes()
	return nil
}

func (vb *VoteBLSMgr) getAddrFromVote(voteType VoteType, round *big.Int, payload []byte, vote *SingleVote) (vrfpk *ecdsa.PublicKey, err error) {
	//prepare validators reader
	var vld state.ValidatorReader
	if round.Cmp(vb.currRound) == 0 {
		if voteType == Certificate {
			vld = vb.lbCertVld
		} else {
			vld = vb.lbVld
		}
	} else {
		lbType := params.LookBackStake
		if voteType == Certificate {
			lbType = params.LookBackCertStake
		}
		tempVld, err := vb.lbMgr.GetLookBackVldReader(nil, round, lbType)
		if err != nil {
			return nil, err
		}
		vld = tempVld
	}
	_, pk, vrfpk, err := vb.Verifier.RecoverSignerInfo(vld.GetValidators(), vote)
	if err != nil {
		err = fmt.Errorf("getAddrFromVote error: %v", err)
		logging.Error("RecoverSignerInfo failed", "err", err)
		return
	}
	sig, err := vb.Verifier.GetBlsSig(vote.Signature)
	if err != nil {
		return nil, err
	}

	err = pk.Verify(payload, sig)
	return vrfpk, err
}

func (vb *VoteBLSMgr) RecoverSignerInfo(vs *state.Validators, vote *SingleVote) (signer *state.Validator, pk bls.PublicKey, vrfpk *ecdsa.PublicKey, err error) {
	return vb.Verifier.RecoverSignerInfo(vs, vote)
}
