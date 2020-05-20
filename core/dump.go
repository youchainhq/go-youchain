// Copyright 2020 YOUCHAIN FOUNDATION LTD.
// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"github.com/youchainhq/go-youchain/common"

	"math/big"
)

type DumpTxdata struct {
	AccountNonce uint64          `json:"nonce"`
	Price        *big.Int        `json:"gasPrice"`
	GasLimit     uint64          `json:"gas"`
	Recipient    *common.Address `json:"to"` // nil means contract creation
	Amount       *big.Int        `json:"value"`
	Payload      []byte          `json:"input"`

	// Signature values
	V string `json:"v"`
	R string `json:"r"`
	S string `json:"s"`

	// This is only used when marshaling to JSON.
	Hash common.Hash `json:"hash"`
}
type DumpList struct {
	Transaction map[uint64]DumpTxdata `json:"txlist"`
}
type DumpTransaction struct {
	TxList map[string]DumpList `json:"address"`
}

func (pool *TxPool) RawDump(queue map[common.Address]*txList) DumpTransaction {
	rawpending := queue

	dump := DumpTransaction{
		TxList: make(map[string]DumpList),
	}
	for addr, txlist := range rawpending {
		txs := txlist.txs.items
		address, err := addr.MarshalText()
		if err != nil {
			panic(err)
		}
		dumplist := DumpList{
			Transaction: make(map[uint64]DumpTxdata),
		}
		for _, value := range txs {

			v, r, s := value.RawSignatureValues()
			var nonce = value.Nonce()
			txdata := DumpTxdata{
				AccountNonce: value.Nonce(),
				Price:        value.GasPrice(),
				GasLimit:     value.Gas(),
				Recipient:    value.To(),
				Amount:       value.Value(),
				Payload:      value.Data(),
				Hash:         value.Hash(),
				V:            v.String(),
				R:            r.String(),
				S:            s.String(),
			}
			dumplist.Transaction[nonce] = txdata
		}
		dump.TxList[common.Bytes2Hex(address)] = dumplist

	}

	return dump
}

type DumpAllTx struct {
	Pending DumpTransaction
	Queue   DumpTransaction
}
