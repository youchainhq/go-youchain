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

package you

import (
	"fmt"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/p2p"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"sync"
	"testing"
	"time"
)

var testAccount, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")

func TestStatusMsgErrors8(t *testing.T) {
	testStatusMsgErrors(t, you8)
}

func testStatusMsgErrors(t *testing.T, protocol int) {
	pm, _ := newTestProtocolManagerMust(t, 0, nil, nil)

	var (
		head    = pm.blockchain.CurrentHeader()
		genesis = pm.blockchain.Genesis()
		height  = head.Number.Uint64()
	)

	defer pm.Stop()

	tests := []struct {
		code      uint64
		data      interface{}
		wantError error
	}{
		{
			code: TxMsg, data: []interface{}{},
			wantError: errResp(ErrNoStatusMsg, "first msg has code 3 (!= 0)"),
		},
		{
			code: StatusMsg, data: statusData{10, params.NetworkIdForTestCase, 0, height, head.Hash(), genesis.Hash()},
			wantError: errResp(ErrProtocolVersionMismatch, "10 (!= %d)", protocol),
		},
		{
			code: StatusMsg, data: statusData{uint32(protocol), 999, 0, height, head.Hash(), genesis.Hash()},
			wantError: errResp(ErrNetworkIdMismatch, "999 (!= 99)"),
		},
		{
			code: StatusMsg, data: statusData{uint32(protocol), DefaultConfig.NetworkId, 0, height, head.Hash(), common.Hash{3}},
			wantError: errResp(ErrGenesisBlockMismatch, "0300000000000000 (!= %x)", genesis.Hash().Bytes()[:8]),
		},
	}

	for i, test := range tests {
		p, errc := newTestPeer(t, "peer", protocol, pm, false)
		ty := p.Node().Nodetype().String()
		fmt.Println(ty)
		go p2p.Send(p.app, test.code, test.data)

		select {
		case err := <-errc:
			if err == nil {
				t.Errorf("test %d: protocol returned nil error, want %q", i, test.wantError)
			} else if err.Error() != test.wantError.Error() {
				t.Errorf("test %d: wrong error: got %q, want %q", i, err, test.wantError)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("protocol did not shut down within 5 seconds")
		}
		p.close()
	}
}

func TestRecvTransaction8(t *testing.T) {
	testRecvTransaction(t, you8)
}

func testRecvTransaction(t *testing.T, protocol int) {
	txAdded := make(chan types.Transactions)
	pm, _ := newTestProtocolManagerMust(t, 0, nil, txAdded)
	p, _ := newTestPeer(t, "peer", protocol, pm, true)

	defer pm.Stop()
	defer p.close()

	tx := newTestTransaction(testAccount, 0, 0)
	if err := p2p.Send(p.app, TxMsg, []interface{}{tx}); err != nil {
		t.Fatalf("send error: %v", err)
	}
	select {
	case added := <-txAdded:
		if len(added) != 1 {
			t.Errorf("wrong number of added transactions: got %d, want 1", len(added))
		} else if added[0].Hash() != tx.Hash() {
			t.Errorf("added wrong tx hash: got %v, want %v", added[0].Hash(), tx.Hash())
		}
	case <-time.After(2 * time.Second):
		t.Errorf("no NewTxsEvent received within 2 seconds")
	}
}

func TestSendTransaction8(t *testing.T) {
	testSendTransaction(t, you8)
}

func testSendTransaction(t *testing.T, protocol int) {
	pm, _ := newTestProtocolManagerMust(t, 0, nil, nil)
	defer pm.Stop()
	const txsize = txsyncPackSize / 10
	alltxs := make([]*types.Transaction, 10)

	for nonce := range alltxs {
		alltxs[nonce] = newTestTransaction(testAccount, uint64(nonce), txsize)
	}

	pm.txpool.AddRemotes(alltxs)
	var wg sync.WaitGroup

	checktxs := func(p *testPeer) {
		defer wg.Done()
		defer p.close()
		seen := make(map[common.Hash]bool)
		for _, tx := range alltxs {
			seen[tx.Hash()] = false
		}

		for n := 0; n < len(alltxs) && !t.Failed(); {
			var txs []*types.Transaction
			msg, err := p.app.ReadMsg()

			if err != nil {
				t.Errorf("%v: read error: %v", p.Peer, err)
			} else if msg.Code != TxMsg {
				t.Errorf("%v: got code %d, want TxMsg", p.Peer, msg.Code)
			}
			if err := msg.Decode(&txs); err != nil {
				t.Errorf("%v: %v", p.Peer, err)
			}

			for _, tx := range txs {
				hash := tx.Hash()
				seentx, want := seen[hash]
				if seentx {
					t.Errorf("%v: got tx more than once: %x", p.Peer, hash)
				}
				if !want {
					t.Errorf("%v: got unexpected tx: %x", p.Peer, hash)
				}

				seen[hash] = true
				n++
			}
		}
	}

	//for i := 0; i < 3; i++ {
	p, _ := newTestPeer(t, fmt.Sprintf("peer #%d", 1), protocol, pm, true)
	wg.Add(1)
	go checktxs(p)
	//}
	wg.Wait()
}

func TestHashOrNumber_EncodeRLP(t *testing.T) {
	a := &HashOrNumber{Number: 2322323323}
	bs, _ := rlp.EncodeToBytes(a)
	fmt.Println(hexutil.Encode(bs))
}

func TestPeer_BlocksData(t *testing.T) {
	y := []BlocksData{}
	//x := make(BlocksData, 10)
	//bs, _ := rlp.EncodeToBytes(x)
	//fmt.Println(hexutil.Encode(bs))
	bs, _ := rlp.EncodeToBytes(y)
	fmt.Println(hexutil.Encode(bs))

}
