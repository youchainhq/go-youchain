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
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"math/big"
	"time"
)

type InvalidMsgMaker struct {
	sk *ecdsa.PrivateKey
}

func (m *InvalidMsgMaker) DecodeFailedMsg() []byte {
	round := big.NewInt(10)
	ev := getSendMessageEvent(round)
	msg := getMessage(ev, m.sk)
	ev2 := getMessageEvent(msg, round)
	ev2.Payload = ev2.Payload[3:]
	logging.Info("MakeInvalidMsg.", "type", "DecodeFailedMsg")

	return ev2.Payload
}

func (m *InvalidMsgMaker) InvalidSignature() []byte {
	round := big.NewInt(10)
	ev := getSendMessageEvent(round)

	//msg := &Message{Code: ev.Code, Payload: ev.Payload}
	//// need to append signature
	//payload := append(ev.Payload, int8ToBytes(uint8(10))...)	// use the wrong code
	//signature, err := Sign(m.sk, payload)
	//if err != nil {
	//	logging.Error("ucon: sign payload failed")
	//	return nil
	//}
	msg := getMessage(ev, m.sk)
	msg.Signature = msg.Signature[2:]

	ev2 := getMessageEvent(msg, round)
	logging.Info("MakeInvalidMsg.", "type", "InvalidSignature")
	return ev2.Payload
}

func (m *InvalidMsgMaker) InvalidAddress() []byte {
	round := big.NewInt(10)
	ev := getSendMessageEvent(round)

	sk, _ := crypto.GenerateKey()
	msg := getMessage(ev, sk)
	ev2 := getMessageEvent(msg, round)
	logging.Info("MakeInvalidMsg.", "type", "InvalidAddress")

	return ev2.Payload
}

func (m *InvalidMsgMaker) InvalidSize() []byte {
	round := big.NewInt(10)
	ev := getSendMessageEvent(round)
	msg := getMessage(ev, m.sk)
	for i := 0; i < 3; i++ {
		msg.Payload = append(msg.Payload, msg.Payload...)
	}
	logging.Info("MsgSize", "value", len(msg.Payload))

	ev2 := getMessageEvent(msg, round)
	logging.Info("MakeInvalidMsg.", "type", "InvalidSize")

	return ev2.Payload
}

func (m *InvalidMsgMaker) InvalidVoteMsg() []byte {
	return nil
}

func (m *InvalidMsgMaker) DecodePayloadFailed() []byte {
	round := big.NewInt(10)
	ev := getSendMessageEvent(round)
	msg := getMessage(ev, m.sk)
	msg.Payload = append(msg.Payload, []byte{0x11}...)

	ev2 := getMessageEvent(msg, round)
	return ev2.Payload
}

func (m *InvalidMsgMaker) EmptyRound() []byte {
	round := big.NewInt(10)
	ev := getSendMessageEvent(nil)
	msg := getMessage(ev, m.sk)

	ev2 := getMessageEvent(msg, round)
	return ev2.Payload
}

func (m *InvalidMsgMaker) completeMakingProcess() []byte {
	round := big.NewInt(10)
	msg1 := &BlockHashWithVotes{
		Priority:   common.Hash{0x01},
		BlockHash:  common.Hash{0x01},
		Round:      round,
		RoundIndex: uint32(1),
		Vote:       nil,
		Timestamp:  uint64(time.Now().Unix()),
	}
	ecp, err := Encode(msg1)
	if err != nil {
		logging.Error("encode BlockHashWithVotes message failed: ", msg1, err)
		return nil
	}

	ev1 := &SendMessageEvent{
		Code:    VoteTypeToMsgCode(Prevote),
		Payload: ecp,
		Round:   round,
	}

	msg2 := Message{Code: ev1.Code, Payload: ev1.Payload}
	// need to append signature
	payload := append(ev1.Payload, int8ToBytes(uint8(ev1.Code))...)
	signature, err := Sign(m.sk, payload)
	if err != nil {
		logging.Error("ucon: sign payload failed")
		return nil
	}
	msg2.Signature = signature

	ecm, err := msg2.Encode()
	if err != nil {
		logging.Error("ucon: encode message failed")
		return nil
	}

	ev2 := &MessageEvent{
		Payload: ecm,
		Code:    MessageCodeToString(ev1.Code),
		Round:   round,
	}
	//p2p.Send(p.rw, you.ConsensusMsg, ev.Payload)

	return ev2.Payload
}

func getSendMessageEvent(round *big.Int) *SendMessageEvent {
	voteInfo := &SingleVote{
		Votes:     0,
		Signature: nil,
		Proof:     nil,
	}
	msg := &BlockHashWithVotes{
		Priority:   common.Hash{0x01},
		BlockHash:  common.Hash{0x01},
		Round:      round,
		RoundIndex: uint32(1),
		Vote:       voteInfo,
		Timestamp:  uint64(time.Now().Unix()),
	}
	ecp, err := Encode(msg)
	if err != nil {
		logging.Error("encode BlockHashWithVotes message failed: ", msg, err)
		return nil
	}

	ev1 := &SendMessageEvent{
		Code:    VoteTypeToMsgCode(Prevote),
		Payload: ecp,
		Round:   round,
	}
	return ev1
}

func getMessage(ev *SendMessageEvent, sk *ecdsa.PrivateKey) *Message {
	msg := &Message{Code: ev.Code, Payload: ev.Payload}
	// need to append signature
	payload := append(ev.Payload, int8ToBytes(uint8(ev.Code))...)
	signature, err := Sign(sk, payload)
	if err != nil {
		logging.Error("ucon: sign payload failed")
		return nil
	}
	msg.Signature = signature

	return msg
}

func getMessageEvent(msg *Message, round *big.Int) *MessageEvent {
	ecm, err := msg.Encode()
	if err != nil {
		logging.Error("ucon: encode message failed")
		return nil
	}

	ev := &MessageEvent{
		Payload: ecm,
		Code:    MessageCodeToString(msg.Code),
		Round:   round,
	}

	return ev
}
