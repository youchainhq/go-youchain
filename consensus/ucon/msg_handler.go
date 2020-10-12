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
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
)

type MsgReceivedStatus uint8

const (
	msgOldRound MsgReceivedStatus = iota
	msgOldRoundIndex
	msgSame
	msgFuture
	msgInvalid
)

var ErrInvalidConsensusMsg = errors.New("invalid consensus message")

type ProcessReceivedMsgFn func(event ReceivedMsgEvent) (error, bool)

type ProcessPriorityMsg func(msg *CachedPriorityMessage, status MsgReceivedStatus) (error, bool)
type ProcessProposedBlockMsg func(msg *CachedBlockMessage, status MsgReceivedStatus) (error, bool)
type ProcessVoteMsg func(ev VoteMsgEvent, status MsgReceivedStatus) (error, bool)

type MessageHandler struct {
	rawSk *ecdsa.PrivateKey

	lock           sync.Mutex
	round          *big.Int
	roundIndex     uint32
	step           uint32
	cachedMessages *CachedMsgMgr // the structure adaptive for (Round, RoundIndex)
	getValidatorFn GetLookBackValidatorFn
	processMsgFn   ProcessReceivedMsgFn

	eventMux *event.TypeMux // send notifications
	eventSub *event.TypeMuxSubscription

	processPriorityMsgFn      ProcessPriorityMsg
	processProposedBlockMsgFn ProcessProposedBlockMsg
	processVoteMsgFn          ProcessVoteMsg

	allowedFutureMsgTime time.Duration // allowed max time of future message
}

func NewMessageHandler(rawSk *ecdsa.PrivateKey,
	eventMux *event.TypeMux,
	getValidatorFn GetLookBackValidatorFn,
	processMsgFn ProcessReceivedMsgFn,
	processPriotiryMsg ProcessPriorityMsg,
	processProposedBlockMsg ProcessProposedBlockMsg,
	processVoteMsg ProcessVoteMsg) *MessageHandler {
	mh := &MessageHandler{
		rawSk:                     rawSk,
		eventMux:                  eventMux,
		getValidatorFn:            getValidatorFn,
		processMsgFn:              processMsgFn,
		processPriorityMsgFn:      processPriotiryMsg,
		processProposedBlockMsgFn: processProposedBlockMsg,
		processVoteMsgFn:          processVoteMsg,
		allowedFutureMsgTime:      10 * time.Second,
	}
	mh.cachedMessages = InitCachedMessages()

	return mh
}

func (mh *MessageHandler) Start() {
	mh.eventSub = mh.eventMux.Subscribe(SendMessageEvent{}, ContextChangeEvent{}, TransferMessageEvent{})

	go mh.eventLoop()
}

func (mh *MessageHandler) Stop() {
	mh.eventSub.Unsubscribe()
}

func (mh *MessageHandler) updateContext(ev ContextChangeEvent) {
	mh.lock.Lock()
	defer mh.lock.Unlock()

	if ev.Round == nil {
		return
	}
	if mh.round == nil || mh.round.Cmp(ev.Round) != 0 {
		mh.round = ev.Round
		mh.roundIndex = ev.RoundIndex
		//mh.clearReceivedMsg()
		//mh.clearSentMsg()
		mh.cachedMessages.Clear(ev.Round.Uint64(), ev.RoundIndex)
	} else {
		mh.roundIndex = ev.RoundIndex
	}
	mh.step = ev.Step
	if mh.step == UConStepStart {
		mh.processCachedMsgs()
	}
}

func (mh *MessageHandler) eventLoop() {
	for obj := range mh.eventSub.Chan() {
		if obj == nil {
			return
		}
		switch ev := obj.Data.(type) {
		case SendMessageEvent:
			mh.sendMsg(ev)
		case TransferMessageEvent:
			mh.transferMsg(ev)
		case ContextChangeEvent:
			mh.updateContext(ev)
		}
	}
}

func (mh *MessageHandler) sendMsg(ev SendMessageEvent) (common.Hash, error) {
	//logging.Info("sendMsg", "code", MessageCodeToString(ev.Code), "size", len(ev.Payload))
	m := Message{Code: ev.Code, Payload: ev.Payload}

	// need to append signature
	payload := append(ev.Payload, int8ToBytes(uint8(ev.Code))...)
	signature, err := Sign(mh.rawSk, payload)
	if err != nil {
		logging.Error("ucon: sign payload failed")
		return common.Hash{0}, fmt.Errorf("ucon: sign payload failed")
	}
	m.Signature = signature
	//m.ReceivedAt = uint64(time.Now().Unix())

	ecm, err := m.Encode()
	if err != nil {
		logging.Error("ucon: encode message failed")
		return common.Hash{0}, fmt.Errorf("ucon: encode message failed")
	}

	// gossip message
	mh.eventMux.AsyncPost(MessageEvent{Payload: ecm, Code: MessageCodeToString(ev.Code), Round: ev.Round})

	logging.Info("SendMsg.", "ev code", MessageCodeToString(ev.Code), "Round", ev.Round, "RoundIndex", mh.roundIndex, "Code", MessageCodeToString(m.Code),
		"Msg", m.PayloadHash().String())

	return m.PayloadHash(), nil
}

func (mh *MessageHandler) transferMsg(ev TransferMessageEvent) {
	// gossip message
	mh.eventMux.AsyncPost(MessageEvent{Payload: ev.Payload, Code: MessageCodeToString(ev.Code), Round: ev.Round})

	//logging.Debug("TransferMessageEvent.", "code", MessageCodeToString(ev.Code), "Round", ev.Round)
}

func (mh *MessageHandler) HandleMsg(data []byte, receivedAt time.Time) error {
	dcm, err := Decode(data)
	if err != nil {
		logging.Error("ucon: decode from msg.data failed")
		return fmt.Errorf("ucon: decode from msg.data failed")
	}

	// extract public key from Signature
	payload := append(dcm.Payload, int8ToBytes(uint8(dcm.Code))...)
	pubKey, err := GetSignaturePublicKey(payload, dcm.Signature)
	if err != nil {
		logging.Error("get Signature public key failed.", "err", err)
		return err
	}

	pk, err := secp256k1VRF.NewVRFVerifier(pubKey)
	if err != nil {
		logging.Error("get pubKey failed.", "err", err)
		return err
	}
	addr := crypto.PubkeyToAddress(*pubKey)

	// provide a function to process message based on (Round, RoundIndex)
	var msgRound *big.Int
	var msgRoundIndex uint32
	judger := func(round *big.Int, roundIndex uint32, sendAt uint64, msgType MsgType) (MsgReceivedStatus, error) {
		// don't process msg from a round which is smaller then round-OldRoundMaxInterval
		if mh.round != nil && mh.round.Cmp(round) > 0 && mh.round.Uint64()-round.Uint64() > uint64(params.MaxVoteCacheCount) {
			return msgInvalid, nil
		}
		// check the validator status
		lbType := params.LookBackPos
		if msgType == msgCertificate {
			lbType = params.LookBackCert
		}
		val, overLookBack := mh.getValidatorFn(round, addr, lbType)
		if val == nil || val.Status == params.ValidatorOffline || val.Stake.Uint64() == 0 ||
			val.Kind() != params.KindChamber { //(val.Kind() != params.KindChamber && (dcm.Code == msgPriorityProposal || dcm.Code == msgBlockProposal)) {
			if !overLookBack {
				// the sender is a invalid validator. report
				if val != nil {
					logging.Error("GetValidator failed.", "status", val.Status, "stake", val.Stake, "kind", val.Kind())
				}
				return msgInvalid, fmt.Errorf("get validator info failed.")
			}
			return msgInvalid, nil
		}

		//todo metrics
		msgRound = round
		msgRoundIndex = roundIndex

		if mh.round != nil && round.Cmp(mh.round) < 0 {
			return msgOldRound, nil
		}
		if mh.round != nil && round.Cmp(mh.round) == 0 {
			if mh.roundIndex == roundIndex {
				// If the timestamp is far ahead, then it's still invalid.
				if sendAt > uint64(time.Now().Add(mh.allowedFutureMsgTime).Unix()) {
					logging.Warn("A message far ahead", "addr", addr, "msgType", MessageCodeToString(msgType), "sendAt", time.Unix(int64(sendAt), 0).String())
					return msgInvalid, nil
				}
				return msgSame, nil
			} else if mh.roundIndex > roundIndex {
				return msgOldRoundIndex, nil
			}
		}

		return msgFuture, nil
	}

	//
	judgeTime := func(round *big.Int, roundIndex uint32, sendAt uint64) (error, bool) {
		evt := ReceivedMsgEvent{
			Round:      round,
			RoundIndex: roundIndex,
			Addr:       addr,
			ReceivedAt: receivedAt, //uint64(receivedAt.Unix()),
			SendAt:     sendAt,
		}
		//err, isValid := mh.processMsgFn(evt)
		//if err != nil {
		//	return isValid, fmt.Errorf("time judge failed.")
		//}
		return mh.processMsgFn(evt)
	}

	logging.Debug("ReceivedMsg.", "Code", MessageCodeToString(dcm.Code), "addr", addr.String())
	msgStatus := msgInvalid
	switch dcm.Code {
	case msgPriorityProposal:
		dcp := &ConsensusCommon{}
		err := dcm.DecodePayload(dcp)
		if err != nil {
			logging.Error("DecodePayload msgPriorityProposal failed", "err", err)
			return err
		}
		if len(dcm.Payload) > PriorityMsgSize {
			logging.Error("MsgSizeNotMatch", "size", len(dcm.Payload), "custom", PriorityMsgSize)
			return fmt.Errorf("MsgSizeNotMatch")
		}
		//log.Info("msgPriorityProposal.","msg",dcp,"local-Round",mh.round)

		msgStatus, err = judger(dcp.Round, dcp.RoundIndex, dcp.Timestamp, dcm.Code)
		if err != nil {
			return err
		}
		if msgStatus == msgOldRound || msgStatus == msgInvalid {
			return nil
		}

		cache := &CachedPriorityMessage{
			data:      data,
			msg:       dcm,
			pubKey:    pubKey,
			vrfPK:     pk,
			consensus: dcp,
		}
		err, invalid := mh.processPriorityMsgFn(cache, msgStatus)
		//verify message priority, invalid=true, return err, put in blacklist,
		//invalid=false, won't put in blacklist
		if invalid {
			logging.Error("ProcessPriorityMsg failed", "err", err)
			return ErrInvalidConsensusMsg
		}
		if err != nil {
			return nil
		}
		err, passedTimeCheck := judgeTime(dcp.Round, dcp.RoundIndex, dcp.Timestamp)
		//check the validator information and the time interval
		//err is not nil, put in blacklist
		//passedTimeCheck=false, don't broadcast this message
		if err != nil {
			return err
		}
		if msgStatus == msgFuture {
			mh.cachedMessages.NewMessage(cache, dcm.Code, addr, receivedAt)
		}
		if !passedTimeCheck {
			return nil
		}

	case msgBlockProposal:
		block := &types.Block{}
		err := dcm.DecodePayload(block)
		if err != nil {
			logging.Error("DecodePayload msgBlockProposal failed", "err", err)
			return err
		}

		consensusData, err := GetConsensusDataFromHeader(block.Header())
		if err != nil {
			logging.Error("GetConsensusDataFromHeader msgBlockProposal failed", "err", err)
			return err
		}

		msgStatus, err = judger(consensusData.Round, consensusData.RoundIndex, block.Time(), dcm.Code)
		if err != nil {
			return err
		}
		if msgStatus == msgOldRound || msgStatus == msgOldRoundIndex || msgStatus == msgInvalid {
			return nil
		}

		cache := &CachedBlockMessage{
			data:       data,
			msg:        dcm,
			pubKey:     pubKey,
			vrfPK:      pk,
			block:      block,
			round:      consensusData.Round,
			roundIndex: consensusData.RoundIndex,
		}
		err, invalid := mh.processProposedBlockMsgFn(cache, msgStatus)
		//invalid=true, return err, put in blacklist,
		//invalid=false, won't put in blacklist, return nil
		if invalid {
			logging.Error("ProcessProposedBlockMsg failed", "err", err)
			return ErrInvalidConsensusMsg
		}
		if err != nil {
			return nil
		}
		err, passedTimeCheck := judgeTime(consensusData.Round, consensusData.RoundIndex, block.Time())
		//check the validator information and the time interval
		//err is not nil, put in blacklist
		//passedTimeCheck=false, don't broadcast this message
		if err != nil {
			return err
		}
		if msgStatus == msgFuture {
			mh.cachedMessages.NewMessage(cache, dcm.Code, addr, receivedAt)
		}
		if !passedTimeCheck {
			return nil
		}

	case msgPrevote:
		fallthrough
	case msgPrecommit:
		fallthrough
	case msgCertificate:
		fallthrough
	case msgNext:
		votesMsg := &BlockHashWithVotes{}
		err := dcm.DecodePayload(votesMsg)
		if err != nil {
			logging.Error("DecodePayload failed.", "Round", mh.round, "RoundIndex", mh.roundIndex, "address", addr.String(), "Msg", dcm.PayloadHash().String(), err)
			return err
		}

		if len(dcm.Payload) > VoteMsgSize {
			logging.Error("MsgSizeNotMatch", "size", len(dcm.Payload), "custom", VoteMsgSize)
			return fmt.Errorf("MsgSizeNotMatch")
		}

		//log.Info("received msgPrevote", votesMsg)
		if votesMsg.Round == nil || votesMsg.Round.Uint64() == 0 {
			logging.Error("Empty Round. ", "Round", mh.round, "RoundIndex", mh.roundIndex, "address", addr.String(), "Msg", dcm.PayloadHash().String())
			return fmt.Errorf("Empty Round.")
		}

		msgStatus, err = judger(votesMsg.Round, votesMsg.RoundIndex, votesMsg.Timestamp, dcm.Code)
		if err != nil {
			return err
		}
		if msgStatus == msgInvalid {
			return nil
		}
		if dcm.Code == msgPrecommit && (msgStatus == msgOldRound || msgStatus == msgOldRoundIndex) {
			logging.Debug("ReceivedOldVote.", "Round", msgRound, "RoundIndex", msgRoundIndex, "Addr", addr.String())
		}

		cache := &CachedVotesMessage{
			data:      data,
			msg:       dcm,
			VotesData: votesMsg,
			addr:      addr,
		}
		err, invalid := mh.processVoteMsgFn(VoteMsgEvent{Msg: cache, VType: MsgCodeToVoteType(dcm.Code)}, msgStatus)
		//invalid=true, return err, put in blacklist,
		//invalid=false, won't put in blacklist, return nil
		if invalid {
			logging.Error("ProcessVoteMsg failed", "err", err)
			return ErrInvalidConsensusMsg
		}
		if err != nil {
			return nil
		}
		err, passedTimeCheck := judgeTime(votesMsg.Round, votesMsg.RoundIndex, votesMsg.Timestamp)
		//check the validator information and the time interval
		//err is not nil, put in blacklist
		//passedTimeCheck=false, don't broadcast this message
		if err != nil {
			return err
		}
		if msgStatus == msgFuture {
			mh.cachedMessages.NewMessage(cache, dcm.Code, addr, receivedAt)
		}
		if !passedTimeCheck {
			return nil
		}

	default:
		logging.Error("UnkownMsgCode.", "Code", dcm.Code)
		return fmt.Errorf("UnkownMsgCode.")
	}

	if msgStatus != msgInvalid {
		logging.Debug("ReceivedMsg.", "Round", msgRound, "RoundIndex", msgRoundIndex,
			"Code", MessageCodeToString(dcm.Code), "addr", addr.String())
		mh.eventMux.AsyncPost(TransferMessageEvent{Code: dcm.Code, Payload: data, Round: msgRound, PayloadHash: dcm.PayloadHash()})
	}

	return nil
}

func (mh *MessageHandler) processCachedMsgs() {
	round, roundIndex := mh.round, mh.roundIndex

	processFn := func(code MsgType) {
		msgs := mh.cachedMessages.GetMessages(round.Uint64(), roundIndex, code)
		if msgs != nil {
			for _, message := range msgs {
				logging.Info("========cached.", "Round", round, "RoundIndex", roundIndex, "Code", MessageCodeToString(code), "Hash", message.Hash().String())
				switch code {
				case msgBlockProposal:
					mh.eventMux.AsyncPost(ProposedBlockMsgEvent{Msg: message.(*CachedBlockMessage)}) //, FromCache:true})
				case msgPriorityProposal:
					mh.eventMux.AsyncPost(PriorityMsgEvent{Msg: message.(*CachedPriorityMessage)}) //, FromCache:true})
				case msgPrevote:
				case msgPrecommit:
				case msgNext:
					mh.eventMux.AsyncPost(VoteMsgEvent{Msg: message.(*CachedVotesMessage), VType: MsgCodeToVoteType(code)}) //, FromCache:true})
				}
			}
			mh.cachedMessages.RemoveMessages(round.Uint64(), roundIndex, code)
		}
	}

	processFn(msgBlockProposal)
	processFn(msgPriorityProposal)
	processFn(msgPrevote)
	processFn(msgPrecommit)
	processFn(msgNext)
}

func (mh *MessageHandler) UpdateAllowedFutureMsgTime(t time.Duration) {
	if t > time.Second {
		mh.allowedFutureMsgTime = t
	}
}
