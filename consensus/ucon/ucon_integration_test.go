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
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"github.com/youchainhq/go-youchain/local"
	"io"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/youchainhq/go-youchain/bls"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/rawdb"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/crypto/vrf"
	"github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/trie"
	"github.com/youchainhq/go-youchain/youdb"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/stretchr/testify/assert"
)

const (
	YouNewBlockMsg  = 0x01
	YouConsensusMsg = 0x08
)

var maxDelay = 20 // maximum communication delay in milliseconds, 0 means no delay.

// global cache for filtering duplicate messages
var msgCache = &cache{items: make(map[common.Hash]int64)}

func TestUcon(t *testing.T) {
	run(t, logging.LvlInfo, "", func(t *testing.T, nodes []*memNode) {
		hasGenBlock := false
	End:
		for i, n := 0, 10; i < n; i++ {
			time.Sleep(10 * time.Second)
			for _, nd := range nodes {
				b := nd.chain.CurrentBlock()
				if b != nil && b.NumberU64() >= uint64(n) {
					hasGenBlock = true
					logging.Info(fmt.Sprintf("current height: %d\n", b.NumberU64()))
					break End
				}
			}
		}
		if !hasGenBlock {
			t.Fatal("chain growing slowly")
		}
	})
}

func TestFork(t *testing.T) {
	run(t, logging.LvlInfo, "", func(t *testing.T, nodes []*memNode) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		ticker := time.NewTicker(time.Second)
		blks := make(map[uint64]map[common.Hash]bool) //blockNumber -> blockHash -> bool
		lastHeight := make(map[common.Address]uint64)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, nd := range nodes {
					lh := lastHeight[nd.my.addr]
					ch := nd.chain.CurrentHeader().Number.Uint64()
					for i := lh + 1; i <= ch; i++ {
						ihash := nd.chain.GetHeaderByNumber(i).Hash()
						if mh, numExist := blks[i]; numExist {
							if _, hashExist := mh[ihash]; !hashExist {
								mh[ihash] = true
								if len(mh) > 1 {
									//detected fork
									strHash := ""
									for k := range mh {
										strHash += k.String() + " "
									}
									t.Errorf("Detected fork! Height: %d Hashes: %s", i, strHash)
									return
								}
							}
						} else {
							blks[i] = make(map[common.Hash]bool)
							blks[i][ihash] = true
						}
					}
					lastHeight[nd.my.addr] = ch
				}
			}
		}
	})
}

func TestACoCHT(t *testing.T) {
	// run on demand. Set the params.ACoCHTFrequency to a smaller value (and must be 8-multiples)
	t.SkipNow()
	if params.ACoCHTFrequency > 128 {
		t.Fatal("Please set the params.ACoCHTFrequency to a smaller value to shorten the test time")
	}

	run(t, logging.LvlWarn, "chain_indexer.go=5,ac_reader.go=5,ac_cht_backend.go=5,blockchain.go=5",
		func(t *testing.T, nodes []*memNode) {
			// check the building of the ACoCHT
			ch := make(chan core.ChainHeadEvent, 2)
			sub := nodes[0].chain.SubscribeChainHeadEvent(ch)
			defer sub.Unsubscribe()
			acreader := rawdb.NewAcReader(nodes[0].db)
			bltDb := trie.NewDatabase(youdb.NewTable(nodes[0].db, core.BloomTrieTablePrefix))
			chtDb := trie.NewDatabase(youdb.NewTable(nodes[0].db, core.ChtTablePrefix))

		End:
			for {
				select {
				case ev := <-ch:
					header := ev.Block.Header()
					logging.Warn("head event", "num", header.Number, "hash", header.Hash().String())
					//logging.Warn("ChainHeadEvent", "num", header.Number.Uint64(), "hash", header.Hash())
					if len(header.ChtRoot) > 0 {
						t.Logf("block: %d, chtRoot: %s, bltRoot: %s", header.Number.Uint64(), hexutil.Encode(header.ChtRoot), hexutil.Encode(header.BltRoot))
					}
					if header.Number.Uint64()%params.ACoCHTFrequency == 0 {
						if len(header.ChtRoot) != 32 {
							t.Errorf("Invalid chtRoot on block %d, got: %s, want a valid 32 byte hash", header.Number.Uint64(), hexutil.Encode(header.ChtRoot))
						}
						if len(header.BltRoot) != 32 {
							t.Errorf("Invalid bltRoot on block %d, got: %s, want a valid 32 byte hash", header.Number.Uint64(), hexutil.Encode(header.BltRoot))
						}
						chtRootDb, bltRootDb, err := acreader.ReadAcNode(header.Number.Uint64(), header.ParentHash)
						assert.NoError(t, err, "read acnode on", header.Number)
						assert.EqualValues(t, chtRootDb, header.ChtRoot, "read chtRoot on", header.Number)
						assert.EqualValues(t, bltRootDb, header.BltRoot, "read bltRoot on", header.Number)
						//restores the trie
						_, err = trie.New(common.BytesToHash(header.ChtRoot), chtDb)
						assert.NoError(t, err, "restore cht")
						_, err = trie.New(common.BytesToHash(header.BltRoot), bltDb)
						assert.NoError(t, err, "restore blt")
					}
					if header.Number.Uint64() > 5*params.ACoCHTFrequency+1 {
						//cancel()
						break End
					}
				}
			}

		})
}

// run is the common start of a test (thought it's non-essential),
// use the `test` function to handle the test result(the block chain),
// and can use the node to query the block chain.
func run(t *testing.T, loglevel logging.Lvl, vmodule string, test func(t *testing.T, nodes []*memNode)) {
	settingLog(loglevel, vmodule)

	genesis := createBasicObjs()
	nodes := initNodePeers(validators)
	var wg sync.WaitGroup //wait for all nodes start.
	var allEngineStartWG sync.WaitGroup
	wg.Add(len(nodes))
	allEngineStartWG.Add(len(nodes))
	for _, nd := range nodes {
		n := nd
		go n.Start(genesis, &wg, &allEngineStartWG)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go deleteExpired(ctx)

	wg.Wait()
	// actual test case
	test(t, nodes)

	//done
	for _, nd := range nodes {
		nd.Stop()
	}
	cancel()
}

func settingLog(loglevel logging.Lvl, vmodule string) {
	logging.PrintOrigins(true)

	usecolor := (isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())) && os.Getenv("TERM") != "dumb"
	output := io.Writer(os.Stderr)
	if usecolor {
		output = colorable.NewColorableStderr()
	}
	ostream := logging.StreamHandler(output, logging.ShortTerminalFormat(usecolor))

	glogger := logging.NewGlogHandler(ostream)
	glogger.Verbosity(loglevel)
	if len(vmodule) > 0 {
		err := glogger.Vmodule(vmodule)
		if err != nil {
			panic(err)
		}
	}

	logging.Root().SetHandler(glogger)
}

func deleteExpired(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			msgCache.DeleteExpired()
		}
	}
}

type peer interface {
	Send(msg msg)
	Address() common.Address
	Stake() *big.Int
	Context() context.Context
}

type msg struct {
	Code    int
	Payload interface{}
}

type account struct {
	addr     common.Address
	rawSk    *ecdsa.PrivateKey
	vrfSk    vrf.PrivateKey
	blsSkStr string
	stake    *big.Int
}

type memNode struct {
	id int

	my    account
	db    youdb.Database
	miner *memMiner
	mux   *event.TypeMux
	peers map[common.Address]peer
	chain *core.BlockChain

	msgEventSub *event.TypeMuxSubscription
	ctx         context.Context
	cancel      context.CancelFunc
	rcvCh       chan msg
	broadcastCh chan msg
	runningFlag int32
}

type memMiner struct {
	engine   consensus.Ucon
	chain    *core.BlockChain
	coinbase common.Address
	mux      *event.TypeMux
	ctx      context.Context

	headEventSub *event.TypeMuxSubscription
}

//
type cache struct {
	mu    sync.RWMutex
	items map[common.Hash]int64
}

func (c *cache) TryAdd(key common.Hash) bool {
	c.mu.RLock()
	_, exist := c.items[key]
	c.mu.RUnlock()
	if !exist {
		c.mu.Lock()
		_, exist = c.items[key]
		if !exist {
			c.items[key] = time.Now().Unix() + 30
		}
		c.mu.Unlock()
	}
	return !exist
}

func (c *cache) Add(key common.Hash) {
	c.mu.Lock()
	c.items[key] = time.Now().Unix() + 30
	c.mu.Unlock()
}

func (c *cache) Exist(key common.Hash) bool {
	c.mu.RLock()
	_, exist := c.items[key]
	c.mu.RUnlock()
	return exist
}

func (c *cache) DeleteExpired() {
	now := time.Now().Unix()
	c.mu.Lock()
	for k, v := range c.items {
		if now > v {
			delete(c.items, k)
		}
	}
	c.mu.Unlock()
}

var (
	hasInit           bool
	genesis           core.Genesis
	genesisValidators = core.GenesisValidators{}
	fullValset        []*ukey
	blsmgr            = bls.NewBlsManager()
	validators        []*account
)

type ukey struct {
	Uconkey       string `json:"uconkey"`
	Uconvalidator int    `json:"uconvalidator"`
	Stake         uint64 `json:"stake"`
	Coinbase      string `json:"coinbase"`
	BLSSignkey    string `json:"blssignkey,omitempty"`
}

func createBasicObjs() core.Genesis {
	if !hasInit {
		genesis = generateGenesis()
		hasInit = true
	}
	return genesis
}

func generateGenesis() (genesis core.Genesis) {
	//read full fullValset
	bf, err := ioutil.ReadFile("./testdata/ucon.json")
	if err != nil {
		logging.Crit("read ucon file failed", "err", err)
	}
	if err := json.Unmarshal(bf, &fullValset); err != nil {
		logging.Crit("unmarshal failed", "err", err)
	}

	fill(1, uint8(params.RoleChancellor))
	fill(5, uint8(params.RoleSenator))
	fill(0, uint8(params.RoleHouse))

	fmt.Println(common.AsJson(genesisValidators))

	gb, err := ioutil.ReadFile("./testdata/genesis_tpl.json")
	if err != nil {
		logging.Crit("read genesis_tpl", "err", err)
	}

	if err = genesis.UnmarshalJSON(gb); err != nil {
		logging.Crit("UnmarshalJSON genesis_tpl", "err", err)
	}

	genesis.Validators = genesisValidators

	// Testing consensus data
	data := &BlockConsensusData{}
	err = rlp.DecodeBytes(genesis.Consensus, data)
	if err != nil {
		logging.Error("GetConsensusDataFromHeader failed.", "err", err)
	}
	logging.Info("ConsensusData", "Round", data.Round, "RI", data.RoundIndex, "Seed", data.Seed.String(),
		"SubUsers", data.SubUsers, "ProposerThreshold", data.ProposerThreshold, "ValidatorThreshold", data.ValidatorThreshold,
		"CertThreshold", data.CertValThreshold, "Priority", data.Priority.String())

	return
}

func fill(count int, role uint8) {
	idxBase := len(genesisValidators)
	for i := 0; i < count; i++ {
		uk := fullValset[idxBase+i]

		priv, _ := crypto.HexToECDSA(uk.Uconkey)
		addr := common.HexToAddress(uk.Coinbase)
		stake := new(big.Int).SetUint64(uk.Stake)

		blssk, err := blsmgr.DecSecretKeyHex(uk.BLSSignkey)
		errorThenFatal(err)
		blspkcp, _ := blssk.PubKey()

		v := core.GenesisValidator{
			OperatorAddress: addr,
			Coinbase:        addr,
			Token:           common.Big1().Mul(stake, params.StakeUint),
			MainPubKey:      crypto.CompressPubkey(&priv.PublicKey),
			BlsPubKey:       blspkcp.Compress().Bytes(),
			Role:            params.ValidatorRole(role),
			Status:          params.ValidatorOnline,
		}
		genesisValidators[addr] = v

		sk, err := crypto.HexToECDSA(uk.Uconkey)
		errorThenFatal(err, "uconkey", uk.Uconkey)
		vrfsk, err := secp256k1VRF.NewVRFSigner(sk)
		va := &account{
			addr:     addr,
			rawSk:    priv,
			vrfSk:    vrfsk,
			blsSkStr: uk.BLSSignkey,
			stake:    v.Token,
		}
		validators = append(validators, va)
		logging.Info("Validator:", "len", len(validators), "token", v.Token, "addr", addr.String())
	}
}

func initNodePeers(validators []*account) []*memNode {
	if maxDelay > 0 {
		rand.Seed(time.Now().UnixNano())
	}
	nodes := make([]*memNode, 0, len(validators))
	for _, va := range validators {
		node := &memNode{id: time.Now().Nanosecond(), my: *va, peers: make(map[common.Address]peer)}
		node.rcvCh = make(chan msg, 100)
		node.broadcastCh = make(chan msg, 100)
		node.ctx, node.cancel = context.WithCancel(context.Background())
		for i := 0; i < len(nodes); i++ {
			nodes[i].peers[node.my.addr] = node
			node.peers[nodes[i].my.addr] = nodes[i]
		}

		nodes = append(nodes, node)
	}
	return nodes
}

func errorThenFatal(err error, v ...interface{}) {
	if err != nil {
		if len(v) > 0 {
			logging.Crit("errorThenFatal", "err", err, v)
		} else {
			logging.Crit("errorThenFatal", "err", err)
		}
	}
}

func (nd *memNode) Send(msg msg) {
	if nd.isRunning() {
		nd.rcvCh <- msg
	}
}

func (nd *memNode) Address() common.Address {
	return nd.my.addr
}

func (nd *memNode) Stake() *big.Int {
	return new(big.Int).Set(nd.my.stake)
}

func (nd *memNode) Context() context.Context {
	return nd.ctx
}

func (nd *memNode) isRunning() bool {
	return atomic.LoadInt32(&nd.runningFlag) == 1
}

func (nd *memNode) Start(genesis core.Genesis, wg *sync.WaitGroup, allEngineWG *sync.WaitGroup) {
	nd.init(genesis)
	nd.msgEventSub = nd.mux.Subscribe(MessageEvent{})

	go nd.receive()
	go nd.broadcast()
	go nd.handleMsg()
	go nd.miner.Start(nd, allEngineWG)

	atomic.StoreInt32(&nd.runningFlag, 1)
	wg.Done()
}

func (nd *memNode) Stop() {
	atomic.StoreInt32(&nd.runningFlag, 0)

	nd.cancel()
	nd.miner.Stop()
	close(nd.broadcastCh)
	close(nd.rcvCh)
}

func (nd *memNode) init(genesis core.Genesis) {
	db := youdb.NewMemDatabase()
	nd.db = db
	nd.mux = new(event.TypeMux)
	engine, err := NewVRFServer(db)
	errorThenFatal(err, "when", "NewVRFServer")
	h, err := core.SetupGenesisBlock(db, genesis.NetworkId, &genesis)
	fmt.Println("genesis hash", h.String())
	errorThenFatal(err, "when", "SetupGenesisBlock")
	//for _, k := range db.Keys() {
	//	v, _ := db.Get(k)
	//	fmt.Printf("%x : %x\n", k, v)
	//}
	chain, err := core.NewBlockChain(db, engine, nd.mux, params.ArchiveNode, local.FakeDetailDB())
	errorThenFatal(err, "when", "NewBlockChain")
	//init pos table, the 'Stake' has a unit of 'YOU'

	nd.chain = chain
	nd.miner = &memMiner{
		engine:   engine,
		chain:    chain,
		coinbase: nd.Address(),
		mux:      nd.mux,
		ctx:      nd.ctx,
	}
}

func (nd *memNode) Insert(block *types.Block) error {
	hash := block.Hash()
	logging.Warn("memNode InsertChain", "id", nd.id, "hash", hash.String())
	if err := nd.miner.chain.InsertChain(types.Blocks{block}); err != nil {
		return err
	}
	//broadcast
	if msgCache.TryAdd(hash) {
		logging.Warn("memNode broadcast", "id", nd.id, "hash", hash)
		if nd.isRunning() {
			nd.broadcastCh <- msg{Code: YouNewBlockMsg, Payload: block}
		}
	}
	return nil
}

func (nd *memNode) broadcast() {
	for m := range nd.broadcastCh {
		//log.Debugf("%s send msg code: %d", nd.my.addr.String(), m.Code)
		for _, p := range nd.peers {
			if maxDelay > 0 {
				// random delay
				delayms := rand.Intn(maxDelay)
				delay := time.Duration(delayms) * time.Millisecond
				go func(pr peer, d time.Duration, m msg) {
					select {
					case <-pr.Context().Done():
						return
					case <-time.After(d):
						pr.Send(m)
					}
				}(p, delay, m)
			} else {
				p.Send(m)
			}
		}
	}
}

func (nd *memNode) receive() {
	for m := range nd.rcvCh {
		switch m.Code {
		case YouNewBlockMsg:
			// A fake logic for the you.fetcher
			blk := m.Payload.(*types.Block)
			logging.Warn("memNode receive InsertChain", "id", nd.id, "hash", blk.Hash().String())
			nd.chain.InsertChain(types.Blocks{blk})
		case YouConsensusMsg:
			me := m.Payload.(MessageEvent)
			nd.miner.engine.HandleMsg(me.Payload, time.Now())
			//if err != nil {
			//	logging.Error("recv ConsensusMsg:", "id", nd.id, "addr", nd.my.addr.String(), "err", err)
			//}
		default:
			logging.Error("unsupported msgCode:", "addr", nd.my.addr.String(), "code", m.Code)
		}
	}
}

func (nd *memNode) handleMsg() {
	defer nd.msgEventSub.Unsubscribe()
	for {
		select {
		case <-nd.ctx.Done():
			return
		case evt := <-nd.msgEventSub.Chan():
			if evt == nil {
				logging.Error("nil event", "addr", nd.my.addr.String())
				return
			}
			switch d := evt.Data.(type) {
			case MessageEvent:
				hash := crypto.Keccak256Hash(d.Payload)
				if msgCache.TryAdd(hash) {
					if nd.isRunning() {
						nd.broadcastCh <- msg{Code: YouConsensusMsg, Payload: d}
					}
				}
			default:
				logging.Error("handleMsg unsupported TypeMuxEvent")
			}
		}
	}
}

func (m *memMiner) Start(nd *memNode, allEngineWG *sync.WaitGroup) {
	m.headEventSub = m.mux.Subscribe(core.ChainHeadEvent{})
	m.engine.SetValKey(nd.my.rawSk, common.FromHex(nd.my.blsSkStr))
	err := m.engine.StartMining(nd.chain, nd, nd.mux)
	allEngineWG.Done()
	errorThenFatal(err, "coinbase", m.coinbase.String(), "when", "engine start")

	time.Sleep(time.Millisecond) //for the other nodes to start

	allEngineWG.Wait()
	err = m.commitWork()
	if err != nil {
		logging.Error("commitWork error", "coinbase", m.coinbase.String(), "err", err)
		return
	}

	go func() {
		defer m.headEventSub.Unsubscribe()
		for {
			select {
			case <-m.ctx.Done():
				return
			case evt := <-m.headEventSub.Chan():
				// A real event arrived, process interesting content
				if evt == nil {
					logging.Error("nil event", "coinbase", m.coinbase.String())
					return
				}
				switch evt.Data.(type) {
				case core.ChainHeadEvent:
					logging.Debug("recv mux chainhead")
					//using channel to sync
					err = m.commitWork()
					if nil != err {
						logging.Error("commitwork failed", "coinbase", m.coinbase.String(), "err", err)
						return
					}
				}
			}
		}
	}()
}

func (m *memMiner) Stop() {
	m.engine.Stop()
}

func (m *memMiner) commitWork() error {
	parent := m.chain.CurrentBlock()

	num := parent.Number()
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     num.Add(num, common.Big1()),
		GasRewards: big.NewInt(0),
		Subsidy:    big.NewInt(0),
		Time:       uint64(time.Now().Unix()),
		Coinbase:   m.coinbase,
		GasLimit:   core.CalcGasLimit(parent),
	}
	// processing protocol version state
	if err := core.ProcessYouVersionState(parent.Header(), header); err != nil {
		logging.Crit("fatal at ProcessYouVersionState", "err", err)
	}

	if err := m.engine.Prepare(m.chain, header); err != nil {
		bh, err1 := json.Marshal(header)
		if err1 == nil {
			logging.Info(fmt.Sprintf("%s header: %s \n", m.coinbase.String(), string(bh)))
		} else {
			logging.Info(fmt.Sprintf("%s marshal header error: %v", m.coinbase.String(), err1))
		}
		return nil
	}
	statedb, err := m.chain.StateAt(parent.Root(), parent.ValRoot(), parent.StakingRoot())
	if err != nil {
		return fmt.Errorf("chain.StateAt return error: %v", err)
	}

	block, err := m.engine.FinalizeAndAssemble(m.chain, header, statedb, nil, nil)
	errorThenFatal(err)
	stop := make(chan struct{})
	_, err = m.engine.Seal(m.chain, block, stop)
	if err != nil {
		return fmt.Errorf("engine.Seal return error: %v", err)
	}

	return nil
}

func TestVrfSortition2(t *testing.T) {
	t.SkipNow() //run on need
	type UconConfig struct {
		UconKey  string `json:"uconkey"`
		Coinbase string `json:"coinbase"`
		Stake    int    `json:"stake"`
	}
	bs, err := ioutil.ReadFile("./testdata/ucon.json")
	errorThenFatal(err, "when", "read uconfile")

	var ucons []UconConfig
	err = json.Unmarshal(bs, &ucons)
	errorThenFatal(err, "when", "unmarshal uconfile")

	first10, last10 := make([]*account, 0, 10), make([]*account, 0, 10)
	l := len(ucons) - 1
	cvt := func(uc UconConfig) *account {
		addr := common.HexToAddress(uc.Coinbase)
		sk, err := crypto.HexToECDSA(uc.UconKey)
		errorThenFatal(err)
		vrfsk, err := secp256k1VRF.NewVRFSigner(sk)
		errorThenFatal(err)
		va := &account{
			addr:  addr,
			rawSk: sk,
			vrfSk: vrfsk,
			stake: big.NewInt(int64(uc.Stake)),
		}
		return va
	}
	total := 0
	for i := 0; i < 10; i++ {
		fa := cvt(ucons[i])
		la := cvt(ucons[l-i])
		la.stake = new(big.Int).Set(fa.stake)
		first10 = append(first10, fa)
		last10 = append(last10, la)
		total += ucons[i].Stake
	}
	totalYou := big.NewInt(int64(total))

	rand.Seed(time.Now().UnixNano())
	sorti := func(a *account, sd common.Hash, j int) int {
		_, _, fj := VrfSortition(a.vrfSk, sd, uint32(j+1), 2, 10, a.stake, totalYou)
		return int(fj)
	}
	var fwin, lwin int
	fresult, lresult := make([]int, 0, 1000), make([]int, 0, 1000)

	for j := 0; j < 1000; j++ {
		var sd common.Hash
		rand.Read(sd[:])
		if j < 10 {
			fmt.Printf("%x\n", sd.Bytes())
		}
		var fv, lv int
		for i := 0; i < 10; i++ {
			fv += sorti(first10[i], sd, j)
			lv += sorti(last10[i], sd, j)
		}
		fresult = append(fresult, fv)
		lresult = append(lresult, lv)
		if fv > lv {
			fwin++
		} else if lv > fv {
			lwin++
		}
	}
	sort.Ints(fresult)
	sort.Ints(lresult)
	fmt.Printf("fwin: %d \nlwin: %d \nfresult(min,p25,p50,p75,max): %d,%d,%d,%d,%d  \nlresult(min,p25,p50,p75,max): %d,%d,%d,%d,%d\n", fwin, lwin, fresult[0], fresult[250], fresult[500], fresult[750], fresult[999], lresult[0], lresult[250], lresult[500], lresult[750], lresult[999])
}
