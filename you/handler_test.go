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
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/you/downloader"
	"math/big"
	"sync"
	"testing"
)

type testTxPool struct {
	pool    []*types.Transaction
	lock    sync.RWMutex // Protects the transaction pool
	txP2pCh chan<- core.NewTxsEvent
}

// AddRemotes should add the given transactions to the pool.
func (p *testTxPool) AddRemotes(txs types.Transactions) []error {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.pool = append(p.pool, txs...)
	return make([]error, len(txs))
}

//// Pending should return pending transactions.
//// The slice should be modifiable by the caller.
//Pending() (map[common.Address]types.Transactions, error)

// SubscribeNewTxsEvent should return an event subscription of
// NewTxsEvent and send events to the given channel.
func (p *testTxPool) SubscribeP2pEvent(ch chan<- core.NewTxsEvent) {
	p.txP2pCh = ch
}

// SubscribeNewTxsEvent registers a subscription of NewTxsEvent and
// starts sending event to the given channel.
func (pool *testTxPool) SubscribeNewTxsEvent(ch chan<- core.NewTxsEvent) event.Subscription {
	//return pool.scope.Track(pool.txFeed.Subscribe(ch))
	return nil
}

// Pending retrieves all currently processable transactions, groupped by origin
// account and sorted by nonce. The returned transaction set is a copy and can be
// freely modified by calling code.
func (pool *testTxPool) Pending() (map[common.Address]types.Transactions, error) {
	//pool.mu.Lock()
	//defer pool.mu.Unlock()
	//
	//pending := make(map[common.Address]types.Transactions)
	//for addr, list := range pool.pending {
	//	pending[addr] = list.Flatten()
	//}
	//return pending, nil
	return nil, nil
}

//func TestProtocolManager(t *testing.T) {
//	wg := sync.WaitGroup{}
//	wg.Add(1)
//
//	chainDb := youdb.NewMemDatabase()
//	config := &DefaultConfig
//	networkConfig, _, genesisErr := core.SetupGenesisBlock(chainDb, config.Genesis)
//	if genesisErr != nil {
//		t.Fatal(genesisErr)
//	}
//	bc, _ := core.NewBlockChain(chainDb, networkConfig, dummy.NewDummy(), new(event.TypeMux), false)
//	bc.Start()
//
//	pool := &testTxPool{}
//	//
//	//networkCon := p2p.NetworkConfig{
//	//	ListenPort: 3007,
//	//	Seed:       []string{},
//	//	DataDir:    node.DefaultConfig.ResolvePath("p2p"),
//	//}
//
//	p, err := NewProtocolManager(params.TestnetConfig, pool, bc, nil, nil, nil, downloader.FullSync)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	p.Start(nil, 100)
//
//	wg.Wait()
//
//}

func TestHandleGetHeadersMsg(t *testing.T) {
	var query = getBlockHeadersData{}
	query.Origin = HashOrNumber{Number: 18971}
	query.Skip = 1
	query.Amount = 3
	query.Reverse = false

	var (
		headers []uint64
		unknown bool
	)

	for !unknown && len(headers) < int(query.Amount) && len(headers) < downloader.MaxHeaderFetch {
		origin := query.Origin.Number

		headers = append(headers, origin)

		switch {
		case !query.Reverse:
			// Number based traversal towards the leaf block
			query.Origin.Number += query.Skip + 1
		}
	}

	fmt.Println(len(headers))
	for e := range headers {
		fmt.Println(e, headers[e])
	}
}

func TestSizeLimit(t *testing.T) {
	var bytes common.StorageSize
	headers := &types.Header{}

	txs := []*types.Transaction{}
	res := []*types.Receipt{}

	signer := types.NewYouSigner(params.NetworkIdForTestCase)
	k, _ := crypto.GenerateKey()

	for i := 0; i < 5000; i++ {
		tx := types.NewTransaction(uint64(100), common.StringToAddress("1"), big.NewInt(100), uint64(100), big.NewInt(100), nil)
		signedTx, _ := types.SignTx(tx, signer, k)
		txs = append(txs, signedTx)
		res = append(res, types.NewReceipt(common.StringToHash("1").Bytes(), false, uint64(10000)))
	}

	block := types.NewBlock(headers, txs, res)
	bytes += block.Size()
	fmt.Println(bytes)

	//data := make(BlocksData, 1)

	var data BlocksData
	data = append(data, struct {
		Block  *types.Block
		Number *big.Int
	}{Block: block, Number: big.NewInt(10000)})

	size, r, err := rlp.EncodeToReader(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(size)
	fmt.Println(r)

}
