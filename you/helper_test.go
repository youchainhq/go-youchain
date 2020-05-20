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
	"crypto/ecdsa"
	"crypto/rand"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/consensus/solo"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/p2p"
	"github.com/youchainhq/go-youchain/p2p/enode"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/you/downloader"
	"github.com/youchainhq/go-youchain/youdb"
	"math/big"
	"sort"
	"sync"
	"testing"
)

var (
	testBankKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	testBank       = crypto.PubkeyToAddress(testBankKey.PublicKey)
)

func init() {
	params.InitNetworkId(params.NetworkIdForTestCase)
}

func newTestProtocolManager(blocks int, generator func(int, *core.BlockGen), newtx chan<- types.Transactions) (*ProtocolManager, *youdb.MemDatabase, error) {
	var (
		evmux  = new(event.TypeMux)
		engine = solo.NewSolo()
		db     = youdb.NewMemDatabase()
		gspec  = &core.Genesis{
			NetworkId:   params.NetworkIdForTestCase,
			CurrVersion: params.YouV1,
			Alloc:       core.GenesisAlloc{testBank: {Balance: big.NewInt(1000000)}},
		}
		genesis       = gspec.MustCommit(db)
		blockchain, _ = core.NewBlockChain(db, engine, evmux)
		//TODO: register modules to the processor if needed
	)

	chain, _ := core.GenerateChain(genesis, solo.NewSolo(), db, blocks, blockchain.Processor(), generator)
	if err := blockchain.InsertChain(chain); err != nil {
		panic(err)
	}

	pm, err := NewProtocolManager(&addedTxPool{added: newtx}, blockchain, engine, evmux, db, downloader.FullSync)
	if err != nil {
		return nil, nil, err
	}
	pm.Start(nil, 1000)
	return pm, db, nil
}

// newTestProtocolManagerMust creates a new protocol manager for testing purposes,
// with the given number of blocks already known, and potential notification
// channels for different events. In case of an error, the constructor force-
// fails the test.
func newTestProtocolManagerMust(t *testing.T, blocks int, generator func(int, *core.BlockGen), newtx chan<- types.Transactions) (*ProtocolManager, *youdb.MemDatabase) {
	pm, db, err := newTestProtocolManager(blocks, generator, newtx)
	if err != nil {
		t.Fatalf("Failed to create protocol manager: %v", err)
	}
	return pm, db
}

type addedTxPool struct {
	txFeed event.Feed
	pool   types.Transactions
	added  chan<- types.Transactions

	lock sync.RWMutex // Protects the transaction pool
}

// AddRemotes appends a batch of transactions to the pool, and notifies any
// listeners if the addition channel is non nil
func (p *addedTxPool) AddRemotes(txs types.Transactions) []error {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.pool = append(p.pool, txs...)
	if p.added != nil {
		p.added <- txs
	}
	return make([]error, len(txs))
}

// Pending returns all the transactions known to the pool
func (p *addedTxPool) Pending() (map[common.Address]types.Transactions, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	batches := make(map[common.Address]types.Transactions)
	for _, tx := range p.pool {
		from, _ := types.Sender(types.MakeSigner(big.NewInt(0)), tx)
		batches[from] = append(batches[from], tx)
	}
	for _, batch := range batches {
		sort.Sort(types.TxByNonce(batch))
	}
	return batches, nil
}

func (p *addedTxPool) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	return p.txFeed.Subscribe(ch)
}

// newTestTransaction create a new dummy transaction.
func newTestTransaction(from *ecdsa.PrivateKey, nonce uint64, datasize int) *types.Transaction {
	tx := types.NewTransaction(nonce, common.Address{}, big.NewInt(0), 100000, big.NewInt(0), make([]byte, datasize))
	tx, _ = types.SignTx(tx, types.MakeSigner(big.NewInt(0)), from)
	return tx
}

type testPeer struct {
	net p2p.MsgReadWriter
	app *p2p.MsgPipeRW
	*peer
}

func newTestPeer(t *testing.T, name string, version int, pm *ProtocolManager, shake bool) (*testPeer, <-chan error) {
	app, net := p2p.MsgPipe()

	var id enode.ID
	rand.Read(id[:])

	peer := pm.newPeer(version, p2p.NewPeer(id, name, nil), net)

	// Start the peer on a new thread
	errc := make(chan error, 1)
	go func() {
		select {
		case pm.newPeerCh <- peer:
			errc <- pm.handle(peer, nil)
		case <-pm.quitSync:
			errc <- p2p.DiscQuitting
		}
	}()

	tp := &testPeer{app: app, net: net, peer: peer}

	if shake {
		var (
			genesis = pm.blockchain.Genesis()
			head    = pm.blockchain.CurrentHeader()
			height  = head.Number.Uint64()
		)

		tp.handshake(t, height, head.Hash(), genesis.Hash())
	}

	return tp, errc
}

func (p *testPeer) handshake(t *testing.T, height uint64, head common.Hash, genesis common.Hash) {
	msg := &statusData{
		ProtocolVersion: uint32(p.version),
		NetworkId:       params.NetworkIdForTestCase,
		Height:          height,
		CurrentBlock:    head,
		GenesisBlock:    genesis,
	}

	if err := p2p.ExpectMsg(p.app, StatusMsg, msg); err != nil {
		t.Fatalf("status recv: %v", err)
	}
	if err := p2p.Send(p.app, StatusMsg, msg); err != nil {
		t.Fatalf("status send: %v", err)
	}
}

func (p *testPeer) close() {
	p.app.Close()
}
