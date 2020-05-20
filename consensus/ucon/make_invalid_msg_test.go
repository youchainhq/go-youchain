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
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"testing"
)

func TestInvalidMsgMaker_DecodeFailedMsg(t *testing.T) {
	sk, _ := crypto.GenerateKey()
	m := &InvalidMsgMaker{sk: sk}
	data := m.DecodeFailedMsg()

	_, err := Decode(data)
	if err != nil {
		logging.Error("ucon: decode from msg.data failed", "err", err)
		return
	}
}

func TestInvalidMsgMaker_InvalidSignature(t *testing.T) {
	sk, _ := crypto.GenerateKey()
	m := &InvalidMsgMaker{sk: sk}
	data := m.InvalidSignature()

	dcm, err := Decode(data)
	if err != nil {
		logging.Error("ucon: decode from msg.data failed")
		return
	}

	// extract public key from Signature
	payload := append(dcm.Payload, int8ToBytes(uint8(dcm.Code))...)
	_, err = GetSignaturePublicKey(payload, dcm.Signature)
	if err != nil {
		logging.Error("get Signature public key failed.", "err", err)
		return
	}
}

func TestInvalidMsgMaker_InvalidAddress(t *testing.T) {
	sk, _ := crypto.GenerateKey()
	m := &InvalidMsgMaker{sk: sk}
	data := m.InvalidAddress()

	dcm, err := Decode(data)
	if err != nil {
		logging.Error("ucon: decode from msg.data failed")
		return
	}

	// extract public key from Signature
	payload := append(dcm.Payload, int8ToBytes(uint8(dcm.Code))...)
	pubKey, err := GetSignaturePublicKey(payload, dcm.Signature)
	if err != nil {
		logging.Error("get Signature public key failed.", "err", err)
		return
	}
	addr := crypto.PubkeyToAddress(*pubKey)

	orgAddr := crypto.PubkeyToAddress(sk.PublicKey)
	if addr != orgAddr {
		logging.Error("Address is different.", "addr", addr.String(), "orgAddr", orgAddr.String())
	}
}

func TestInvalidMsgMaker_InvalidSize(t *testing.T) {
	sk, _ := crypto.GenerateKey()
	m := &InvalidMsgMaker{sk: sk}
	data := m.InvalidSize()

	dcm, err := Decode(data)
	if err != nil {
		logging.Error("ucon: decode from msg.data failed")
		return
	}

	if len(dcm.Payload) > VoteMsgSize {
		logging.Error("MsgSizeNotMatch", "size", len(dcm.Payload), "custom", VoteMsgSize)
		return
	}
}

func TestInvalidMsgMaker_DecodePayloadFailed(t *testing.T) {
	sk, _ := crypto.GenerateKey()
	m := &InvalidMsgMaker{sk: sk}
	data := m.DecodePayloadFailed()

	dcm, err := Decode(data)
	if err != nil {
		logging.Error("ucon: decode from msg.data failed")
		return
	}

	votesMsg := &BlockHashWithVotes{}
	err = dcm.DecodePayload(votesMsg)
	if err != nil {
		logging.Error("DecodePayload failed.", "err", err)
		return
	}
}

func TestInvalidMsgMaker_EmptyRound(t *testing.T) {
	sk, _ := crypto.GenerateKey()
	m := &InvalidMsgMaker{sk: sk}
	data := m.EmptyRound()

	dcm, err := Decode(data)
	if err != nil {
		logging.Error("ucon: decode from msg.data failed")
		return
	}

	votesMsg := &BlockHashWithVotes{}
	err = dcm.DecodePayload(votesMsg)
	if err != nil {
		logging.Error("DecodePayload failed.", "err", err)
		return
	}

	if votesMsg.Round.Uint64() == 0 {
		logging.Error("Empty Round. ")
		return
	}
}
