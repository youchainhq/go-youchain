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
	"fmt"
	"github.com/youchainhq/go-youchain/consensus/solo"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/local"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/youdb"
	"math/big"
	"testing"
)

func init() {
	params.InitNetworkId(params.NetworkIdForTestCase)
}

func TestGenerateChain(t *testing.T) {
	var (
		evmux   = new(event.TypeMux)
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		key2, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
		key3, _ = crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
		addr1   = crypto.PubkeyToAddress(key1.PublicKey)
		addr2   = crypto.PubkeyToAddress(key2.PublicKey)
		addr3   = crypto.PubkeyToAddress(key3.PublicKey)
		db      = youdb.NewMemDatabase()
	)
	params.InitNetworkId(params.NetworkIdForTestCase)
	gspec := &Genesis{
		NetworkId:   params.NetworkIdForTestCase,
		Alloc:       GenesisAlloc{addr1: {Balance: big.NewInt(1000000)}},
		CurrVersion: params.YouCurrentVersion,
	}

	genesis := gspec.MustCommit(db)
	signer := types.MakeSigner(big.NewInt(0))
	chain, _ := GenerateChain(genesis, solo.NewSolo(), db, 5, testProcessor(), func(i int, gen *BlockGen) {

		switch i {
		case 0:
			tx, _ := types.SignTx(types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(10000), params.TxGas, nil, nil), signer, key1)
			gen.AddTx(tx)
		case 1:
			// In block 2, addr1 sends some more ether to addr2.
			// addr2 passes it on to addr3.
			tx1, _ := types.SignTx(types.NewTransaction(gen.TxNonce(addr1), addr2, big.NewInt(1000), params.TxGas, nil, nil), signer, key1)
			tx2, _ := types.SignTx(types.NewTransaction(gen.TxNonce(addr2), addr3, big.NewInt(1000), params.TxGas, nil, nil), signer, key2)
			gen.AddTx(tx1)
			gen.AddTx(tx2)
		case 2:
			gen.SetCoinbase(addr3)
			gen.SetExtra([]byte("yeehaw"))
		case 3:
			b2 := gen.PrevBlock(1).Header()
			b2.Extra = []byte("foo")

			b3 := gen.PrevBlock(2).Header()
			b3.Extra = []byte("foo")
		}
	})

	blockchain, _ := NewBlockChain(db, solo.NewSolo(), evmux, params.ArchiveNode, local.FakeDetailDB())
	defer blockchain.Stop()

	if err := blockchain.InsertChain(chain); err != nil {
		t.Errorf("insert error : %v\n", err)
		return
	}

	state, _ := blockchain.State()

	fmt.Printf("last block: #%d\n", blockchain.CurrentBlock().Number())
	fmt.Println("balance of addr1:", state.GetBalance(addr1))
	fmt.Println("balance of addr2:", state.GetBalance(addr2))
	fmt.Println("balance of addr3:", state.GetBalance(addr3))
}
