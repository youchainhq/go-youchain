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
	"sync"
	"sync/atomic"
	"time"

	"github.com/youchainhq/go-youchain/bls"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/crypto/vrf"
	secp256k1VRF "github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/youdb"

	lru "github.com/hashicorp/golang-lru"
)

const (
	UConStepStart       uint32 = 0
	UConStepProposal           = 1 // 1
	UConStepPrevote            = 2 // 2
	UConStepPrecommit          = 4 // 4
	UConStepCertificate        = 5

	stakingCacheLimit = 10
)

type Server struct {
	db youdb.Database

	//todo hold these together
	mainAddress common.Address
	rawSk       *ecdsa.PrivateKey
	vrfSk       vrf.PrivateKey
	blsSk       bls.SecretKey

	blsMgr         bls.BlsManager
	chain          consensus.ChainReader
	alreadyStarted int32
	currentRound   *big.Int
	roundIndex     uint32
	nextIndex      uint32

	currRoundParams *params.CaravelParams
	currParamsLock  sync.RWMutex

	// test speed
	startRound    uint64
	startTime     time.Time
	lastRoundTime time.Time
	startCount    uint64
	timeoutCount  uint64

	proposal     *Proposal
	sortitionMgr *SortitionManager
	msgHandler   *MessageHandler
	voter        *Voter
	timer        *TimerManager

	blsVerifier *BlsVerifier

	vldReaderCache *lru.Cache

	quitChan chan bool
	inserter consensus.MineInserter

	eventMux *event.TypeMux // send notifications
	eventSub *event.TypeMuxSubscription

	skLock          sync.RWMutex
	startMiningLock sync.Mutex
}

func NewVRFServer(db youdb.Database) (*Server, error) {
	server := &Server{
		db:     db,
		blsMgr: bls.NewBlsManager(),
	}
	server.blsVerifier = NewBlsVerifier(server.blsMgr)

	return server, nil
}

//SetValKey sets the validator key
func (s *Server) SetValKey(sk *ecdsa.PrivateKey, blsKeyBytes []byte) (err error) {
	logging.Info("SetValKey.")
	var blsSk bls.SecretKey
	if len(blsKeyBytes) != bls.SecretKeyBytes {
		logging.Error("SetValKey failed.")
		return errors.New("need bls secret key")
	} else {
		blsSk, err = s.blsMgr.DecSecretKey(blsKeyBytes)
		if err != nil {
			logging.Error("SetValKey failed.", "err", err)
			return err
		}
	}
	if sk == nil {
		logging.Error("SetValKey failed.")
		return errors.New("sk must not be nil")
	}
	vrfSk, err := secp256k1VRF.NewVRFSigner(sk)
	if err != nil {
		logging.Error("SetValKey failed.", "err", err)
		return err
	}
	s.skLock.Lock()
	isMining := s.isMining()
	if isMining {
		logging.Error("try to stop mining to change the validator key")
		s.Stop()
	}

	//update keys
	s.mainAddress = crypto.PubkeyToAddress(sk.PublicKey)
	s.rawSk = sk
	s.vrfSk = vrfSk
	s.blsSk = blsSk

	if isMining {
		logging.Warn("try to start mining after changing the validator key")
		err = s.StartMining(s.chain, s.inserter, s.eventMux)
	}
	s.skLock.Unlock()
	return
}

func (s *Server) GetValMainAddress() common.Address {
	return s.mainAddress
}

// StartMining starts the engine to mine
func (s *Server) StartMining(chain consensus.ChainReader, inserter consensus.MineInserter, eventMux *event.TypeMux) error {
	if s.rawSk == nil {
		return consensus.ErrValKeyNotSet
	}
	if s.blsSk == nil {
		return consensus.ErrBlsKeyNotSet
	}
	s.startMiningLock.Lock()
	defer s.startMiningLock.Unlock()
	if s.isMining() {
		logging.Info("Ucon Already Started")
		return nil
	}

	s.quitChan = make(chan bool, 1)
	s.eventMux = eventMux
	s.chain = chain
	s.inserter = inserter

	s.timer = NewTimerManager(s.processTimeout, s.processStepEvent)

	s.sortitionMgr = NewSortitionManager(s.vrfSk, s.getLookbackStakeInfo, s.getLookBackSeed, s.mainAddress)

	s.proposal = NewProposal(eventMux, s.verifyPriority, s.startVote)

	s.voter = NewVoter(s.db, s.rawSk, s.blsSk, eventMux, s.verifySortition,
		s.sortitionMgr.isValidator, s.proposal.blockhashWithMaxPriority,
		s.proposal.getBlockInCache, s.getLookbackStakeInfo, s.getLookbackValidatorsCount,
		s)

	s.blsVerifier = s.voter.blsMgr.Verifier

	s.msgHandler = NewMessageHandler(s.rawSk, eventMux, s.GetLookBackValidator,
		s.processReceiveMsgEvent,
		s.proposal.processPriorityMessage, s.proposal.processProposedBlockMsg, s.voter.processVoteMsg)

	s.vldReaderCache, _ = lru.New(stakingCacheLimit)

	logging.Info("======addr", "addr", s.mainAddress.String())
	logging.Info("Ucon Start")

	err := s.StartNewRound(true)
	if err != nil {
		return err
	}

	s.eventSub = s.eventMux.Subscribe(core.InsertBlockEvent{}, CommitEvent{}, RoundIndexChangeEvent{}, UpdateExistedHeaderEvent{}) //, ReceivedMsgEvent{})
	go s.eventLoop()

	s.msgHandler.Start()
	s.proposal.Start()
	s.voter.Start(s)
	s.timer.Start()

	atomic.StoreInt32(&s.alreadyStarted, 1)
	return nil
}

func (s *Server) Restart() error {
	if s.rawSk == nil {
		return consensus.ErrValKeyNotSet
	}
	if s.blsSk == nil {
		return consensus.ErrBlsKeyNotSet
	}
	s.startMiningLock.Lock()
	defer s.startMiningLock.Unlock()
	if s.isMining() {
		logging.Info("Ucon Already Started")
		return nil
	}

	s.quitChan = make(chan bool, 1)

	err := s.StartNewRound(true)
	if err != nil {
		return err
	}

	s.eventSub = s.eventMux.Subscribe(core.InsertBlockEvent{}, CommitEvent{}, RoundIndexChangeEvent{}, UpdateExistedHeaderEvent{}) //, ReceivedMsgEvent{})
	go s.eventLoop()

	s.msgHandler.Start()
	s.proposal.Start()
	s.voter.Start(s)
	s.timer.Start()

	atomic.StoreInt32(&s.alreadyStarted, 1)
	return nil
}

// Stop the engine
func (s *Server) Stop() error {
	if !atomic.CompareAndSwapInt32(&s.alreadyStarted, 1, 0) {
		return nil
	}
	logging.Info("Ucon Stop")

	close(s.quitChan) // <- true

	s.timer.Stop()
	s.proposal.Stop()
	s.voter.Stop()
	s.msgHandler.Stop()

	s.eventSub.Unsubscribe() // quits eventLoop
	return nil
}

func (s *Server) StartNewRound(newRound bool) error {
	err := s.clearData(newRound)
	if err != nil {
		return err
	}

	// to be removed
	if newRound {
		s.startCount += 1
	}
	if s.currentRound != nil && s.startCount > 2 {
		interval := time.Since(s.startTime).Seconds()
		speed := interval / float64(s.currentRound.Uint64()-s.startRound)
		logging.Info("StartNewRound.", "Round", s.currentRound, "Average", speed)
	} else if s.currentRound != nil {
		s.startRound = s.currentRound.Uint64()
		s.startTime = time.Now()
		logging.Info("StartNewRound.")
	}

	// get parameters for current round
	yp, err := s.chain.VersionForRound(s.currentRound.Uint64())
	if err != nil {
		return err
	}
	s.currParamsLock.Lock()
	s.currRoundParams = &yp.CaravelParams
	s.currParamsLock.Unlock()

	s.timer.startTimer(s.currentRound, s.roundIndex, newRound, yp.ConsensusTimeout, yp.ConsensusStepInterval)
	s.processStepEvent(s.timer.counter)

	c1 := s.getLookbackValidatorsCount(s.currentRound, params.KindChamber, params.LookBackStake)
	c2 := s.getLookbackValidatorsCount(s.currentRound, params.KindHouse, params.LookBackStake)
	logging.Info("GetValidatorsCount.", "Round", s.currentRound, params.ValidatorKindToString(params.KindChamber), c1, params.ValidatorKindToString(params.KindHouse), c2)
	return nil
}

// CurrentCaravelParams returns current round caravel parameters
func (s *Server) CurrentCaravelParams() *params.CaravelParams {
	s.currParamsLock.RLock()
	cp := s.currRoundParams
	s.currParamsLock.RUnlock()
	return cp
}

func (s *Server) CertificateParams(round *big.Int) (*params.CaravelParams, error) {
	if round.Uint64()%params.ACoCHTFrequency != 0 {
		return nil, fmt.Errorf("round %d is not a certificate round", round)
	}
	header, err := s.getLookBackHeader(nil, s.chain, round, params.LookBackCert, nil)
	if err != nil {
		return nil, err
	}
	yp, ok := params.Versions[header.CurrVersion]
	if !ok {
		logging.Crit("CertificateParams: version not found", "round", round, "certHeaderNum", header.Number, "version", header.CurrVersion)
	}
	return &yp.CaravelParams, nil
}

// NewChainHead implements consensus.Ucon.NewChainHead
func (s *Server) NewChainHead(block *types.Block) {
	logging.Info("Process ChainHeadEvent")
}

func (s *Server) clearData(newRound bool) error {
	logging.Info("clearData")

	// parse block-consensus-data from current block
	curBlockHeader := s.chain.CurrentHeader()

	prevConsensusData, err := GetConsensusDataFromHeader(curBlockHeader)
	if err != nil {
		logging.Error("get consensus data from header failed", "err", err)
		return err
	}

	if !newRound {
		//s.roundIndex += 1
		s.roundIndex = s.nextIndex
		s.timeoutCount += 1
	} else {
		// the time for one round
		interval := time.Since(s.lastRoundTime).Seconds()
		logging.Info("===round time.", "Round", s.currentRound, "Time", interval, "Timeout-Count", s.timeoutCount)
		s.lastRoundTime = time.Now()

		s.currentRound = big.NewInt(prevConsensusData.Round.Int64() + 1)
		s.roundIndex = 1
		s.nextIndex = 1

		s.sortitionMgr.ClearStepView(s.currentRound)

		logging.Info("New Round.", "Height", curBlockHeader.Number, "Round", s.currentRound)

		//todo metrics
	}

	return nil
}

// NextRound will broadcast ChainHeadEvent to trigger next seal()
func (s *Server) NextRound(ev RoundIndexChangeEvent) error {
	round, roundIndex := ev.Round, ev.RoundIndex //s.getRoundAndIndex()
	if round == nil || s.currentRound == nil || round.Cmp(s.currentRound) != 0 {
		logging.Error("Round is different.", "Round", round, "CurRound", s.currentRound)
		return nil
	}
	nextIndex := roundIndex
	if roundIndex <= s.roundIndex {
		nextIndex += 1
	}

	if nextIndex == s.nextIndex {
		return nil
	}
	s.nextIndex = nextIndex

	logging.Info("NextRound.", "Round", round, "RoundIndex", s.nextIndex, "Before", s.roundIndex)

	//todo metrics
	s.StartNewRound(false)
	if CompareCommonHash(ev.Priority, common.Hash{}) <= 0 {
		s.eventMux.AsyncPost(core.ChainHeadEvent{})
	}
	return nil
}

// event loop for ucon
func (s *Server) eventLoop() {
	for obj := range s.eventSub.Chan() {
		if obj == nil {
			return
		}
		switch ev := obj.Data.(type) {
		case core.InsertBlockEvent:
			_, err := GetConsensusDataFromHeader(ev.Block.Header())
			if err != nil {
				logging.Error("GetConsensusDataFromHeader failed.", "err", err)
			}
		case CommitEvent:
			s.commit(ev)
		case RoundIndexChangeEvent:
			s.NextRound(ev)
		case UpdateExistedHeaderEvent:
			s.updateBlockHeader(ev)
		}
	}
}

func (s *Server) commit(ev CommitEvent) {
	logging.Info("Commit.", "Round", ev.Round, "RoundIndex", ev.RoundIndex, "hash", ev.Block.Hash().String())

	// need append validators' votes info into the block

	getValidatorsFn := func(backType params.LookBackType) ([]byte, error) {
		ucv, err := s.voter.PackVotes(ev, backType)
		if err != nil {
			logging.Error("Commit failed.", "Round", ev.Round, "RoundIndex", ev.RoundIndex, "get validators failed.", err)
			return nil, err
		}

		ucValidators, err := ucv.ValidatorsToByte()
		if err != nil {
			logging.Error("Commit failed.", "Round", ev.Round, "RoundIndex", ev.RoundIndex, "get validators failed.", err)
			return nil, err
		}
		return ucValidators, nil
	}

	header := ev.Block.Header()

	validators, err := getValidatorsFn(params.LookBackPos)
	if err != nil {
		return
	}
	header.Validator = validators

	//if ev.ChamberCerts != nil {
	certs, err := getValidatorsFn(params.LookBackCert)
	if err != nil {
		return
	}
	header.Certificate = certs
	//}

	ev.Block = ev.Block.WithSeal(header)
	//logging.Info("Commit append UconValidators succeed.", "Round", ev.Round, "RoundIndex", ev.RoundIndex,
	//	"ValSize", len(validators), "CertSize", len(certs), "HeaderSize", len(ev.Block.Validator()))

	err = s.inserter.Insert(ev.Block)
	if err != nil {
		logging.Error("InsertChain failed", "Round", ev.Round, "RoundIndex", ev.RoundIndex, "hash", ev.Block.Hash().String(), "err", err)

		s.voter.removeMarkedBlock(ev.Block.Hash())
	}
}

func (s *Server) updateBlockHeader(ev UpdateExistedHeaderEvent) {
	//block := s.chain.GetBlock(ev.BlockHash, ev.Round.Uint64())
	//if block == nil {
	//	return
	//}
	blockHead := s.chain.GetHeaderByHash(ev.BlockHash)
	if blockHead == nil {
		return
	}

	cp, ucValidators, chamberAddrs, houseAddrs, err := s.GetValidatorAddrs(s.chain, blockHead)
	if err != nil {
		logging.Error("UpdateExistedHeader failed. Get UconValidators failed.", "Round", ev.Round, "RoundIndex", ev.RoundIndex, "err", err)
		return
	}
	logging.Info("UpdateExistedHeader before.", "Round", ev.Round, "Chamber", len(chamberAddrs),
		"House", len(houseAddrs))

	existFn := func(addr common.Address, voterAddrs []common.Address) bool {
		for _, voteAddr := range voterAddrs {
			if addr == voteAddr {
				return true
			}
		}
		return false
	}

	//mergeFn is the common function to merge new votes to the existed set.
	mergeFn := func(oldVotes []SingleVote, oldAggrSig []byte, oldVoteAddrs []common.Address, newRawVotes VotesInfoForBlockHash, enableBls bool, kind4log string) (newVotes []SingleVote, newAggrSig []byte, hasNew bool) {
		newVotes = oldVotes
		newAggrSig = oldAggrSig
		var rawBlsSigs [][]byte
		if enableBls {
			rawBlsSigs = make([][]byte, 0, len(newRawVotes)+1)
		}
		for addr, vote := range newRawVotes {
			if len(vote.Signature) > 0 && !existFn(addr, oldVoteAddrs) {
				hasNew = true
				if cp.EnableBls {
					rawBlsSigs = append(rawBlsSigs, vote.Signature)
					vote.Signature = nil
				}
				newVotes = append(newVotes, *vote)
				//logging.Debug("UpdateExistedHeader.", "kind", kind4log,
				//	"Round", ev.Round, "addr", addr.String(), "block", ev.BlockHash.String())
			}
		}
		if hasNew && enableBls {
			rawBlsSigs = append(rawBlsSigs, oldAggrSig)
			aggrSig, err := s.blsVerifier.AggregateSignatures(rawBlsSigs)
			if err != nil {
				logging.Error("UpdateExistedHeader failed.", "err", err)
				// revert all changing on error
				return oldVotes, oldAggrSig, false
			}
			newAggrSig = aggrSig
		}
		return
	}

	// merge votes in block.Header and ev
	ucv := ucValidators
	var hasNewChamber, hasNewHouse bool
	ucv.ChamberCommitters, ucv.SCAggrSig, hasNewChamber = mergeFn(ucv.ChamberCommitters, ucv.SCAggrSig, chamberAddrs, ev.ChamberPrecommits, cp.EnableBls, "Chamber")

	ucv.HouseCommitters, ucv.MCAggrSig, hasNewHouse = mergeFn(ucv.HouseCommitters, ucv.MCAggrSig, houseAddrs, ev.HousePrecommits, cp.EnableBls, "House")

	if !(hasNewChamber || hasNewHouse) {
		return
	}

	header := blockHead

	ucValData, err := ucv.ValidatorsToByte()
	if err != nil {
		logging.Error("UpdateExistedHeader failed.", "Round", ev.Round, "RoundIndex", ev.RoundIndex, "get validators failed.", err)
		return
	}
	header.Validator = ucValData

	// update the block's header in blockchain
	s.chain.UpdateExistedHeader(header)
}

//HandleMsg handles related consensus messages or
// fallback to default procotol manager's handler
func (s *Server) HandleMsg(data []byte, receivedAt time.Time) error {
	err := s.msgHandler.HandleMsg(data, receivedAt)
	return err
}

func (s *Server) processTimeout(round *big.Int, roundIndex uint32) {
	if round == nil || s.currentRound == nil || round.Cmp(s.currentRound) != 0 {
		return
	}

	markedBlock := s.voter.getMarkedBlock(round, s.roundIndex)
	ev := RoundIndexChangeEvent{
		Round:      round,
		RoundIndex: roundIndex,
		Priority:   common.Hash{},
		BlockHash:  common.Hash{},
	}
	if markedBlock != nil {
		ev.BlockHash = markedBlock.BlockHash
		ev.Priority = markedBlock.Priority
	}

	s.NextRound(ev)
}

func (s *Server) processStepEvent(step uint32) {
	cert := false
	if s.currentRound != nil && s.currentRound.Uint64() > 0 && s.currentRound.Uint64()%params.ACoCHTFrequency == 0 {
		cert = true
	}
	s.eventMux.AsyncPost(ContextChangeEvent{Round: s.currentRound, RoundIndex: s.roundIndex, Step: step, Certificate: cert})
}

func (s *Server) processReceiveMsgEvent(ev ReceivedMsgEvent) (error, bool) {
	// return parameters: bool - whether this message is passed this time check
	yp, err := s.chain.VersionForRound(ev.Round.Uint64())
	if err != nil {
		logging.Warn("can't get YOUChain parameters", "round", ev.Round, "err", err)
		return err, false
	}
	blockhash, err := s.GetLookBackBlockHash(&yp.CaravelParams, ev.Round, params.LookBackStake)
	if err != nil {
		logging.Error("GetLookBackBlockHash failed", "round", ev.Round, "ri", ev.RoundIndex, "addr", ev.Addr.String(), "err", err)
		return err, false
	}
	validator := s.GetValidatorByAddress(blockhash, ev.Addr)
	if validator == nil {
		logging.Error("GetValidatorByAddress failed.", "round", ev.Round, "ri", ev.RoundIndex, "addr", ev.Addr.String(), "block", blockhash.String())
		return fmt.Errorf("GetValidatorByAddress failed."), false
	}
	logging.Debug("GetValidatorByAddress succeed.", "round", ev.Round, "ri", ev.RoundIndex, "addr", ev.Addr.String(), "block", blockhash.String())

	chamberNum := s.ValidatorsNumOfKind(blockhash, params.KindChamber)
	houseNum := uint64(0) //:= s.ValidatorsNumOfKind(blockhash, params.KindHouse)
	return nil, s.timer.NewAddressMsg(ev, validator.Kind(), chamberNum, houseNum)
}

func (s *Server) startVote(round *big.Int, roundIndex uint32) bool {
	if round == nil {
		return false
	}

	Th := uint32(float64(s.CurrentCaravelParams().ValidatorThreshold) * DefaultStartVoteProportion)
	return s.voter.existHashOverVotesThreshold(round, roundIndex, Th, Th)
}

func (s *Server) isMining() bool {
	return atomic.LoadInt32(&s.alreadyStarted) == 1
}
