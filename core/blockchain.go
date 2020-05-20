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
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/core/rawdb"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/core/vm"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/youdb"

	lru "github.com/hashicorp/golang-lru"
)

const (
	bodyCacheLimit      = 256
	blockCacheLimit     = 256
	maxFutureBlocks     = 256
	maxTimeFutureBlocks = 30
	badBlockLimit       = 10
	maxSinglePruneSize  = 32 // For light-client, when pruning old data, avoiding to hold the lock for a long time.
	pruneIntervalM      = 10 // Interval(minutes) for ticker of pruning old data
)

var (
	ErrNoGenesis = errors.New("genesis not found in chain")
)

type VldFetcher interface {
	FetchVldTrie(root common.Hash) error
}

type BlockChain struct {
	eventMux *event.TypeMux
	db       youdb.Database
	nodeType params.NodeType

	currentBlock atomic.Value // Current head of the block chain
	hc           *HeaderChain

	fullSyncOrigin *big.Int       // Origin Block of the full-sync. When finding the best-peer, with a same height, then a smaller fullSyncOrigin is better.
	stateCache     state.Database // State database to reuse between imports (contains state cache)
	bodyCache      *lru.Cache     // Cache for the most recent block bodies
	bodyRLPCache   *lru.Cache     // Cache for the most recent block bodies in RLP encoded format
	blockCache     *lru.Cache     // Cache for the most recent entire blocks
	numberCache    *lru.Cache     // Cache for the most recent block numbers
	receiptsCache  *lru.Cache     // Cache for the most recent receipts per block
	futureBlocks   *lru.Cache     // future blocks are blocks added for later processing
	genesisBlock   *types.Block
	nextAcBlock    atomic.Value // verified next AcNode block,

	engine    consensus.Engine
	isUcon    bool
	validator Validator      // block and state validator interface
	processor Processor      // block processor interface
	vmConfig  vm.LocalConfig //TODO: initialize vm local config

	scope             event.SubscriptionScope
	chainHeadFeed     event.Feed
	newMinedBlockFeed event.Feed
	logsFeed          event.Feed
	rmLogsFeed        event.Feed
	chainFeed         event.Feed

	mu      sync.RWMutex // global mutex for locking chain operations
	chainMu sync.RWMutex // blockchain insertion lock
	procmu  sync.RWMutex // block processor lock

	quit          chan bool      // quit channel
	running       int32          // running must be called atomically
	procInterrupt int32          // interrupt signaler for block processing, must be called atomically
	wg            sync.WaitGroup // chain processing wait group for shutting down

	badBlocks *lru.Cache // Bad block cache

	chtIndexer *ChainIndexer
	bltIndexer *ChainIndexer
	chtBackend *ChtIndexerBackend //duplicate for convenience
	bltBackend *BloomWithTrieIndexer
	acReader   rawdb.AcReader

	onFastSyncing int32 // set to 1 when currently is on fast syncing. must be called atomically
	vldFetcher    VldFetcher
}

func NewBlockChain(db youdb.Database, engine consensus.Engine, eventMux *event.TypeMux) (*BlockChain, error) {
	bc := &BlockChain{
		db:         db,
		nodeType:   params.ArchiveNode,
		stateCache: state.NewDatabase(db),
		//signer:                types.MakeSigner(networkConfig, big.NewInt(0)),
		quit:           make(chan bool),
		engine:         engine,
		eventMux:       eventMux,
		fullSyncOrigin: big.NewInt(0),
	}
	_, bc.isUcon = engine.(consensus.Ucon)
	bc.bodyCache, _ = lru.New(bodyCacheLimit)
	bc.bodyRLPCache, _ = lru.New(bodyCacheLimit)
	bc.numberCache, _ = lru.New(headerCacheLimit)
	bc.blockCache, _ = lru.New(blockCacheLimit)
	bc.receiptsCache, _ = lru.New(blockCacheLimit)
	bc.futureBlocks, _ = lru.New(maxFutureBlocks)
	bc.badBlocks, _ = lru.New(badBlockLimit)
	bc.SetProcessor(NewStateProcessor(bc, engine))
	bc.SetValidator(NewBlockValidator(bc))

	var err error
	bc.hc, err = NewHeaderChain(db, bc, engine, bc.isInterrupted)
	if err != nil {
		return nil, err
	}
	// MissingNodesFetcher is an reserved object in case the future need.
	bc.chtIndexer = NewChtIndexer(db, nil, params.ACoCHTFrequency, 0)
	bc.bltIndexer = NewBloomWithTrieIndexer(db, nil, params.ACoCHTFrequency, 0)
	bc.chtBackend = bc.chtIndexer.backend.(*ChtIndexerBackend)
	bc.bltBackend = bc.bltIndexer.backend.(*BloomWithTrieIndexer)
	bc.acReader = rawdb.NewAcReader(db)

	bc.genesisBlock = bc.GetBlockByNumber(0)
	if bc.genesisBlock == nil {
		return nil, ErrNoGenesis
	}

	logging.Info("start blockchain with genesis", "number", bc.genesisBlock.Number(), "hash", bc.genesisBlock.Hash().String(), "root", bc.genesisBlock.Root().String(), "valRoot", bc.genesisBlock.ValRoot().String())
	if err := bc.loadLastState(); err != nil {
		return nil, err
	}

	// Take ownership of this particular state
	go bc.update()
	bc.chtIndexer.Start(bc)
	bc.bltIndexer.Start(bc)
	return bc, nil
}

func NewBlockChainWithType(db youdb.Database, engine consensus.Engine, eventMux *event.TypeMux, t params.NodeType) (*BlockChain, error) {
	if !t.IsValid() {
		return nil, fmt.Errorf("invalid node type: %d", t)
	}
	bc, err := NewBlockChain(db, engine, eventMux)
	if err != nil {
		return bc, err
	}
	bc.nodeType = t
	if bc.IsLight() {
		hash := rawdb.ReadLightStartHeaderHash(db)
		if hash != (common.Hash{}) {
			lightStart := bc.hc.GetHeaderByHash(hash)
			if nil != lightStart {
				bc.hc.storeLightStartHeader(lightStart)
			}
		} else {
			bc.hc.SetLightStartHeader(bc.hc.genesisHeader)
		}

		go bc.pruneOldData()
	}
	return bc, nil
}

func (bc *BlockChain) loop() {
	timer := time.NewTicker(1 * time.Second)

	for {
		select {
		case <-timer.C:
			continue
		case <-bc.quit:
			return
		}
	}
}

func (bc *BlockChain) Start() {
	go bc.loop()
}

func (bc *BlockChain) Stop() {
	if !atomic.CompareAndSwapInt32(&bc.running, 0, 1) {
		return
	}
	bc.chtIndexer.Close()
	bc.bltIndexer.Close()
	// Unsubscribe all subscriptions registered from blockchain
	bc.scope.Close()
	close(bc.quit)
	atomic.StoreInt32(&bc.procInterrupt, 1)
	bc.wg.Wait()

	logging.Warn("Blockchain manager stopped")
}

func (bc *BlockChain) isInterrupted() bool {
	return atomic.LoadInt32(&bc.procInterrupt) == 1
}

func (bc *BlockChain) InsertChain(chain types.Blocks) error {
	// Sanity check that we have something meaningful to import
	if len(chain) == 0 {
		return nil
	}
	// Do a sanity check that the provided chain is actually ordered and linked
	for i := 1; i < len(chain); i++ {
		if chain[i].NumberU64() != chain[i-1].NumberU64()+1 || chain[i].ParentHash() != chain[i-1].Hash() {
			// Chain broke ancestry, log a message (programming error) and skip insertion
			logging.Error("InsertChain: Non contiguous block insert", "number", chain[i].Number(), "hash", chain[i].Hash().String(),
				"parent", chain[i].ParentHash().String(), "prevnumber", chain[i-1].Number(), "prevhash", chain[i-1].Hash().String())

			return fmt.Errorf("non contiguous insert: item %d is #%d [%x…], item %d is #%d [%x…] (parent [%x…])", i-1, chain[i-1].NumberU64(),
				chain[i-1].Hash().Bytes()[:4], i, chain[i].NumberU64(), chain[i].Hash().Bytes()[:4], chain[i].ParentHash().Bytes()[:4])
		}
	}

	// check that the YOUChain protocol version state is following the rules
	i, err := bc.VerifyYouVersionState(chain)
	if err != nil {
		wrapErr := fmt.Errorf("VerifyYouVersionState failed, index=%d versionState=%s err=%v", i, chain[i].Header().VersionStateString(), err)
		logging.Warn(wrapErr.Error())
		return wrapErr
	}

	// Pre-checks passed, start the full block imports
	bc.wg.Add(1)
	bc.chainMu.Lock()
	n, events, logs, err := bc.insertChain(chain)
	bc.chainMu.Unlock()
	bc.wg.Done()

	logging.Info("InsertChain end blocks", "len", len(chain), "index", n, "events", len(events), "logs", len(logs), "err", err)

	//send internal
	bc.PostChainEvents(events, logs)
	return err
}

func (bc *BlockChain) insertChain(chain types.Blocks) (int, []interface{}, []*types.Log, error) {
	var (
		events        = make([]interface{}, 0, len(chain))
		lastCanon     *types.Block
		coalescedLogs []*types.Log
	)

	headers := make([]*types.Header, len(chain))
	seals := make([]bool, len(chain))
	for i, block := range chain {
		headers[i] = block.Header()
		seals[i] = true
	}

	abort, results := bc.engine.VerifyHeaders(bc, headers, seals)
	defer close(abort)

	logging.Info("insertChain current block:", "current height", bc.CurrentBlock().NumberU64(), "hash:", bc.CurrentBlock().Hash().String(), "blocks", len(chain))

	//about ACoCHT validating
	isNeedValidateCHT, isNeedBuildTemp, lastSecHead := bc.isNeedValidateCHT(headers)

	for i, block := range chain {
		// If the chain is terminating, stop processing blocks
		if bc.isInterrupted() {
			logging.Debug("Premature abort during insert chain")
			return 0, events, coalescedLogs, errors.New("aborted")
		}
		err := <-results
		if err == nil {
			err = bc.Validator().ValidateBody(block)
		}

		switch {
		case err == ErrKnownBlock:
			if bc.CurrentBlock().NumberU64() >= block.NumberU64() {
				logging.Debug("insertChain knownblock ", "hash", block.Hash().String(), "number", block.NumberU64(), "<= current", bc.CurrentBlock().NumberU64())
			} else {
				logging.Debug("insertChain knownblock ", "hash", block.Hash().String(), "number", block.NumberU64(), "> current", bc.CurrentBlock().NumberU64())
			}
			events = append(events, ChainEvent{block, block.Hash(), nil})
			continue
		case err == consensus.ErrFutureBlock:
			max := uint64(time.Now().Unix() + maxTimeFutureBlocks)
			if block.Time() > max {
				return i, events, coalescedLogs, fmt.Errorf("future block: %v > %v", block.Time(), max)
			}
			bc.futureBlocks.Add(block.Hash(), block)
			logging.Warn("insertChain ErrFutureBlock", "number", block.NumberU64(), "hash", block.Hash().String(), "current number", bc.CurrentBlock().NumberU64())
			continue
		case err == consensus.ErrUnknownAncestor && bc.futureBlocks.Contains(block.ParentHash()):
			bc.futureBlocks.Add(block.Hash(), block)
			logging.Warn("insertChain ErrUnknownAncestor", "number", block.NumberU64(), "hash", block.Hash().String(), "current number", bc.CurrentBlock().NumberU64())
			continue
		case err == consensus.ErrPrunedAncestor:
			// Ancestor exist, but not in the canonical chain
			logging.Warn("insertChain ErrPrunedAncestor", "number", block.NumberU64(), "hash", block.Hash().String(), "current number", bc.CurrentBlock().NumberU64())
			err = bc.insertSidechain(chain[i:])
			return i, events, coalescedLogs, err

		case err == consensus.ErrExistCanonical:
			logging.Warn("insertChain ErrExistCanonical", "number", block.NumberU64(), "hash", block.Hash().String(), "current number", bc.CurrentBlock().NumberU64(), "i", i)
			if i == 0 {
				abort <- struct{}{}
				err = bc.insertSidechain(chain[i:])
				return i, events, coalescedLogs, err
			} else {
				err = bc.engine.VerifySeal(bc, block.Header())
				if err == nil {
					err = bc.Validator().ValidateBody(block)
					logging.Debug("insertChain validate body:", "err", err)
					if err != nil {
						logging.Error("insertChain ValidateBody failed:", "err", err)
						return i, events, coalescedLogs, err
					}
				} else {
					logging.Error("insertChain verifyHeader failed:", "err", err)
					return i, events, coalescedLogs, err
				}
			}

		case err == consensus.ErrUnknownParentState:
			err = bc.engine.VerifySeal(bc, block.Header())
			if err != nil {
				logging.Error("insertChain verifyHeader failed:", "err", err)
				return i, events, coalescedLogs, err
			}

		case err != nil:
			bc.reportBlock(block, nil, err)
			return i, events, coalescedLogs, err
		}

		//for ucon, try validate CHT
		if isNeedValidateCHT && block.NumberU64() == lastSecHead {
			if err := bc.Validator().ValidateACoCHT(headers, block, i, isNeedBuildTemp); err != nil {
				return i, events, coalescedLogs, err
			}
		}

		var parent *types.Block
		// validate transactions in the block
		parent = bc.GetBlock(block.ParentHash(), block.NumberU64()-1)
		if i == 0 {
			parent = bc.GetBlock(block.ParentHash(), block.NumberU64()-1)
		} else {
			parent = chain[i-1]
		}

		if parent == nil {
			logging.Warn("insertChain parent == nil", block.NumberU64(), block.Hash().String())
			continue
		}

		// Here should never be an error since we already pass the verifyHeader
		yp, err := bc.VersionForRound(block.NumberU64())
		if err != nil {
			return i, events, coalescedLogs, err
		}
		sRoot := StakingRootForNewBlock(yp.StakingTrieFrequency, parent.Header())
		stateDb, err := state.New(parent.Root(), parent.ValRoot(), sRoot, bc.stateCache)
		if err != nil {
			logging.Error("insertChain create state db failed.", "number", block.NumberU64())
			return i, events, coalescedLogs, err
		}

		receipts, logs, usedGas, err := bc.processor.Process(yp, block, stateDb, bc.vmConfig)
		if err != nil {
			logging.Error("insertChain Process failed.", "number", block.NumberU64())
			bc.reportBlock(block, receipts, err)
			return i, events, coalescedLogs, err
		}

		err = bc.Validator().ValidateState(block, parent, stateDb, receipts, usedGas)
		if err != nil {
			bc.reportBlock(block, receipts, err)
			return i, events, coalescedLogs, err
		}

		// process forks
		if err := bc.WriteBlockWithState(block, stateDb, receipts); err != nil {
			return i, events, coalescedLogs, err
		}

		logging.Info("insertChain WriteBlockWithState:", "number", block.NumberU64())

		lastCanon = block

		coalescedLogs = append(coalescedLogs, logs...)
		events = append(events, ChainEvent{block, block.Hash(), logs})

		metricsBlockElapsedGauge.Update(int64(block.Time() - parent.Time()))
		metricsBlockHeightGauge.Update(int64(block.NumberU64()))
	}

	if lastCanon != nil && bc.CurrentBlock().Hash() == lastCanon.Hash() {
		events = append(events, ChainHeadEvent{lastCanon})

		//notify consensus to update
		if bc.engine != nil {
			bc.engine.UpdateContextForNewBlock(lastCanon)
		}

		//send to event bus
		evt := ChainHeadEvent{Block: lastCanon}
		go bc.eventMux.Post(evt)
	}

	return 0, events, coalescedLogs, nil
}

func (bc *BlockChain) isNeedValidateCHT(headers []*types.Header) (isNeedValidateCHT, isNeedBuildTemp bool, lastSecHead uint64) {
	if bc.isUcon {
		firstNum := headers[0].Number.Uint64()
		lastNum := headers[len(headers)-1].Number.Uint64()
		lastSecHead = (lastNum / params.ACoCHTFrequency) * params.ACoCHTFrequency
		if lastSecHead >= firstNum {
			isNeedValidateCHT = true
			if lastSecHead > firstNum {
				isNeedBuildTemp = true
			}
		}
	}
	return
}

// IsUcon returns whether the consensus is Ucon
func (bc *BlockChain) IsUcon() bool {
	return bc.isUcon
}

func (bc *BlockChain) UconLookBackParams() (seedLookBack, stakeLookBack uint64) {
	if bc.isUcon {
		yp, ok := params.Versions[params.YouCurrentVersion]
		if !ok {
			logging.Crit("YouCurrentVersion not exists") // MUST NOT HAPPEN
		}
		return yp.SeedLookBack, yp.StakeLookBack
	}
	return 0, 0
}

func (bc *BlockChain) VerifyAcHeader(header *types.Header, verifiedAcParents []*types.Header) error {
	if !bc.isUcon {
		return errors.New("VerifyAcHeader unsupported for none ucon engine")
	}
	ucon := bc.engine.(consensus.Ucon)
	return ucon.VerifyAcHeader(bc, header, verifiedAcParents)
}

func (bc *BlockChain) insertSidechain(chain types.Blocks) error {
	// Make sure this side chain is safe to be handled by the merge policies（or say: side chain handle policies)
	// make sure this side chain do not contains canonical block, to prevent longest-chain attack
	i := 0
	for l := len(chain); i < l; i++ {
		if canon := bc.GetBlockByNumber(chain[i].NumberU64()); canon == nil || canon.Hash() != chain[i].Hash() {
			break
		}
	}
	chain = chain[i:]
	if len(chain) <= 0 {
		return nil
	}
	err := bc.verifyAllSideChainBlocks(chain)
	if err != nil {
		return err
	}

	// now we can safely handle the side chain with some policies
	var block *types.Block
	for _, block = range chain {
		if !bc.HasBlock(block.Hash(), block.NumberU64()) {
			if err := bc.WriteBlockWithoutState(block); err != nil {
				return err
			}
			logging.Debug("Injected sidechain block",
				"number", block.Number(), "hash", block.Hash().String(),
				"txs", len(block.Transactions()), "gas", block.GasUsed(),
				"root", block.Root())
		}
	}

	// If the number was larger than our local number, we now need to reimport the previous
	// blocks to regenerate the required state
	logging.Info("Importing sidechain to judge number.", "current:", bc.CurrentBlock().NumberU64(), "number:", block.Number(), "hash:", block.Hash().String())
	if block.NumberU64() <= bc.CurrentBlock().NumberU64() {
		logging.Error("Importing sidechain terminate.", "height", block.NumberU64(), "current-height", bc.CurrentBlock().NumberU64())
		return nil
	}

	// Gather all the sidechain hashes (full blocks may be memory heavy)
	var (
		hashes  []common.Hash
		numbers []uint64
	)

	// we choose the longest chain as the canonical chain, in case ErrKnownBlock when ValidateBody
	parent := block.Header() //bc.GetHeader(block.ParentHash(), block.NumberU64()-1)
	local := bc.GetHeaderByNumber(parent.Number.Uint64())
	//log.Debug("Importing sidechain. Start with parent.", "number:", parent.Number, "hash:", parent.Hash().String())
	for parent != nil && (local == nil || !bc.HasState(parent.Root) || local.Hash() != parent.Hash()) {
		// if there is no transactions in block, its state won't be changed
		hashes = append(hashes, parent.Hash())
		numbers = append(numbers, parent.Number.Uint64())

		parent = bc.GetHeader(parent.ParentHash, parent.Number.Uint64()-1)
		local = bc.GetHeaderByNumber(parent.Number.Uint64())
		logging.Debug("Importing sidechain get parent without state.", "number", parent.Number, "hash", parent.Hash().String())
	}
	logging.Debug("Importing sidechain.", "hashes:", len(hashes))

	if parent == nil {
		err := errors.New("missing parent")
		logging.Error("Importing sidechain failed:", "err", err)
		return err
	}
	if len(hashes) > 0 {
		hashes = append(hashes, parent.Hash())
		numbers = append(numbers, parent.Number.Uint64())
	}

	// Import all the pruned blocks to make the state available
	var (
		blocks []*types.Block
		memory common.StorageSize
	)
	for i := len(hashes) - 1; i >= 0; i-- {
		// Append the next block to our batch
		block := bc.GetBlock(hashes[i], numbers[i])
		blocks = append(blocks, block)
		memory += block.Size()

		// If memory use grew too large, import and continue. Sadly we need to discard
		// all raised events and logs from notifications since we're too heavy on the
		// memory here.
		if len(blocks) >= 2048 || memory > 64*1024*1024 {
			logging.Info("Importing heavy sidechain segment", "blocks", len(blocks), "start", blocks[0].NumberU64(), "end", block.NumberU64())
			if _, _, _, err := bc.insertChain(blocks); err != nil {
				logging.Error("insertChain failed", "err", err)
				return err
			}
			blocks, memory = blocks[:0], 0
		}
	}

	if len(blocks) > 0 {
		logging.Info("Importing sidechain segment", "start", blocks[0].NumberU64(), "end", blocks[len(blocks)-1].NumberU64())
		_, _, _, err := bc.insertChain(blocks)
		logging.Error("Importing sidechain finished:", "err", err)
		return err
	}

	return nil
}

func (bc *BlockChain) verifyAllSideChainBlocks(chain types.Blocks) (err error) {
	logging.Debug("verifyAllSideChainBlocks, blocks", "length", len(chain))

	engine, ok := bc.engine.(consensus.Ucon)
	if !ok {
		return nil
	}

	//parents
	firstNum := chain[0].Number()
	parent := bc.GetBlock(chain[0].ParentHash(), firstNum.Uint64()-1)
	if parent == nil {
		logging.Warn("verifyAllSideChainBlocks unknown ancestor: parent is nil")
		return consensus.ErrUnknownAncestor
	}
	parents := []*types.Block{parent}

	//common var
	var lookBackHeader *types.Header
	var lookBackStateDb state.ValidatorReader
	stateDb, err := state.New(parent.Root(), parent.ValRoot(), parent.StakingRoot(), bc.stateCache)
	if err != nil {
		logging.Error("verifyAllSideChainBlocks create state db failed. ", "blockNum", parent.Number(), "err", err)
		return err
	}

	// get parameters for this side chain
	getCaravelParams := func(i int) (yp *params.YouParams, err error) {
		if i < protocolRoundBack {
			yp, err = bc.VersionForRound(chain[i].NumberU64())
		} else {
			version := chain[i-protocolRoundBack].CurrVersion()
			yp2, ok := params.Versions[version]
			if !ok {
				err = fmt.Errorf("YOUChain protocol version not exists. version: %d", version)
			} else {
				yp = &yp2
			}
		}

		return
	}

	//cache non canonical state for use, ONLY cache the state between 0 and last-look-back-index
	maxCachesIndex := -1
	var caches []*state.StateDB
	lastParams, err := getCaravelParams(len(chain) - 1)
	if err != nil {
		return err
	}
	lastLookBack := engine.GetLookBackBlockNumber(&lastParams.CaravelParams, chain[len(chain)-1].Number(), params.LookBackStake)
	if lastLookBack.Cmp(firstNum) >= 0 {
		maxCachesIndex = int(new(big.Int).Sub(lastLookBack, firstNum).Int64())
		logging.Debug("maxCachesIndex ", "maxCachesIndex", maxCachesIndex)
	}

	for i, b := range chain {
		yp, err := getCaravelParams(i)
		if err != nil {
			return err
		}
		ResetStakingTrieOnNewPeriod(yp.StakingTrieFrequency, b.NumberU64(), stateDb)

		getLookbackHeaderFn := func(lbType params.LookBackType) (*types.Header, error) {
			lookBack := engine.GetLookBackBlockNumber(&yp.CaravelParams, b.Number(), lbType)
			logging.Debug("GetLookBackBlockNumber", "blockNumber", b.Number(), " lookBack ", lookBack)
			if firstNum.Cmp(lookBack) > 0 {
				//look back block is in local canonical
				//verify header
				lookBackHeader = bc.GetHeaderByNumber(lookBack.Uint64())
			} else {
				//look back block is in side chain
				lookBackIndex := int(new(big.Int).Sub(lookBack, firstNum).Int64())
				//the i's block in chain is the (i+1)'s block in parents
				lookBackHeader = parents[lookBackIndex+1].Header()
			}

			return lookBackHeader, nil
		}
		getLookBackVldFn := func(lbType params.LookBackType) (state.ValidatorReader, error) {
			lookBack := engine.GetLookBackBlockNumber(&yp.CaravelParams, b.Number(), lbType)
			logging.Debug("GetLookBackBlockNumber", "blockNumber", b.Number(), " lookBack ", lookBack)
			if firstNum.Cmp(lookBack) > 0 {
				//look back block is in local canonical
				//verify header
				lookBackHeader := bc.GetHeaderByNumber(lookBack.Uint64())
				lookBackStateDb, err = bc.GetVldReader(lookBackHeader.ValRoot)
			} else {
				//look back block is in side chain
				lookBackIndex := int(new(big.Int).Sub(lookBack, firstNum).Int64())
				//use cached side chain state
				lookBackStateDb = caches[lookBackIndex]
			}

			return lookBackStateDb, nil
		}

		seedHeader, err := getLookbackHeaderFn(params.LookBackSeed)
		if err != nil {
			return err
		}
		lbVld, err := getLookBackVldFn(params.LookBackStake)
		if err != nil {
			return err
		}
		var certSeedHeader *types.Header
		var certVld state.ValidatorReader
		if b.Number().Uint64() > 0 && b.Number().Uint64()%params.ACoCHTFrequency == 0 {
			certSeedHeader, err = getLookbackHeaderFn(params.LookBackCertSeed)
			if err != nil {
				return err
			}
			certVld, err = getLookBackVldFn(params.LookBackCertStake)
			if err != nil {
				return err
			}
		}
		err = engine.VerifySideChainHeader(&yp.CaravelParams, seedHeader, lbVld, certSeedHeader, certVld, b, parents)
		if err != nil {
			return err
		}

		//verify block.
		// Notice: Here we can't use bc.Validator().ValidateBody(b), because ValidateBody will check if the parent block is has state in canonical chain.
		// just to process the transactions and then validate the result
		receipts, _, usedGas, err := bc.processor.Process(yp, b, stateDb, bc.vmConfig)
		if err != nil {
			logging.Error("verifyAllSideChainBlocks Process failed.", "number", b.NumberU64())
			return err
		}

		err = bc.Validator().ValidateState(b, parents[i], stateDb, receipts, usedGas)
		if err != nil {
			return err
		}

		//append parent for next block
		parents = append(parents, b)
		if i <= maxCachesIndex {
			caches = append(caches, stateDb.Copy())
		}
	}

	return nil
}

// return:
// true - process forks based on rules: no empty txs, based on consensus.
// 		  insert new block and update the canonical chain
// false - only store new block on db
func (bc *BlockChain) getWriteState(block *types.Block) bool {
	exist := bc.GetBlockByNumber(block.NumberU64())
	if exist != nil {
		// exist a fork. and the canonical chain's height >= block.NumberU64()
		logging.Warn("inserting duplicated block", "current height", bc.CurrentBlock().NumberU64(), "exist hash", exist.Hash().String(), "new height", block.NumberU64(), "new hash", block.Hash().String())

		if block.NumberU64() < bc.CurrentBlock().NumberU64() ||
			(block.NumberU64() == bc.CurrentBlock().NumberU64() && bc.engine.CompareBlocks(block, bc.CurrentBlock()) <= 0) {
			return false
		}

	} else if block.ParentHash() != bc.CurrentBlock().Hash() {
		// exist a fork. and the canonical chain's height equals to block.NumberU64()-1
		// as under our rules, the canonical chain must be the longest chain
		// insert new block and update the canonical chain
		logging.Warn("insertchain parenthash != currenthash", "height", block.NumberU64(), "hash", block.Hash().String(), "parent", block.ParentHash().String(), "current", bc.CurrentBlock().Hash().String())
	}
	return true
}

func (bc *BlockChain) SubscribeChainHeadEvent(ch chan<- ChainHeadEvent) event.Subscription {
	return bc.scope.Track(bc.chainHeadFeed.Subscribe(ch))
}

func (bc *BlockChain) SubscribeNewMinedBlockEvent(ch chan NewMinedBlockEvent) event.Subscription {
	return bc.scope.Track(bc.newMinedBlockFeed.Subscribe(ch))
}

func (bc *BlockChain) PostChainEvents(events []interface{}, logs []*types.Log) {
	// post event logs for further processing
	if logs != nil {
		bc.logsFeed.Send(logs)
	}

	for _, evt := range events {
		switch ev := evt.(type) {
		case ChainEvent:
			bc.chainFeed.Send(ev)
		case ChainHeadEvent:
			bc.chainHeadFeed.Send(ev)
		case NewMinedBlockEvent:
			bc.newMinedBlockFeed.Send(ev)
		}
	}
}

// WriteBlockWithoutState writes only the block and its metadata to the database,
// but does not write any state. This is used to construct competing side forks
// up to the point where they exceed the canonical total difficulty.
func (bc *BlockChain) WriteBlockWithoutState(block *types.Block) error {
	bc.wg.Add(1)
	defer bc.wg.Done()

	bc.mu.Lock()
	defer bc.mu.Unlock()

	//write
	rawdb.WriteBlock(bc.db, block)

	logging.Info("WriteBlockWithoutState.", "Height", block.NumberU64(), "Hash", block.Hash().String())

	return nil
}

// WriteBlockWithState writes the block and all associated state to the database.
func (bc *BlockChain) WriteBlockWithState(block *types.Block, state *state.StateDB, receipts []*types.Receipt) error {
	bc.wg.Add(1)
	defer bc.wg.Done()

	bc.mu.Lock()
	defer bc.mu.Unlock()

	//write
	rawdb.WriteBlock(bc.db, block)

	//db commit
	root, valRoot, stakingRoot, err := state.Commit(true)
	if err != nil {
		logging.Error("state.Commit", err.Error())
		return err
	}

	//todo using statecache
	for key, value := range map[string]common.Hash{"state": root, "val": valRoot, "staking": stakingRoot} {
		if err := state.Database().TrieDB().Commit(value, false); err != nil {
			logging.Error("commit trieDb failed", "trie", key, "err", err)
		}
	}

	logging.Info("WriteBlockWithState: triedb commit", "block", block.Hash().String(), "number", block.NumberU64(), "blockroot", block.Root().String(), "root", root.String(), "valRoot", valRoot.String(), "stakingRoot", stakingRoot)

	batch := bc.db.NewBatch()
	//save receipts to db
	if receipts != nil && len(receipts) > 0 {
		rawdb.WriteReceipts(batch, block.Hash(), block.NumberU64(), receipts)
	}

	if block.ParentHash() != bc.CurrentBlock().Hash() {
		// Reorganise the chain if the parent is not the head block
		if err := bc.reorg(bc.CurrentBlock(), block); err != nil {
			logging.Info("WriteBlockWithState: reorg failed:", "err", err, "number", block.NumberU64(), "hash", block.Hash().String(), "parentHash", block.ParentHash().String())
			return err
		}
	}

	rawdb.WriteTxLookupEntries(batch, block)
	if err := batch.Write(); err != nil {
		return err
	}

	// Set new head.
	bc.insert(block)

	bc.futureBlocks.Remove(block.Hash())

	return nil
}

// reorgs takes two blocks, an old chain and a new chain and will reconstruct the blocks and inserts them
// to be part of the new canonical chain and accumulates potential missing transactions and post an
// event about them
func (bc *BlockChain) reorg(oldBlock, newBlock *types.Block) error {
	var (
		oldChain    types.Blocks
		newChain    types.Blocks
		commonBlock *types.Block

		deletedTxs types.Transactions
		addedTxs   types.Transactions

		deletedLogs []*types.Log
		rebirthLogs []*types.Log

		collectLogs = func(hash common.Hash, removed bool) {
			number := bc.GetBlockNumber(hash)
			if number == nil {
				return
			}
			receipts := rawdb.ReadReceipts(bc.db, hash, *number)
			for _, receipt := range receipts {
				for _, lg := range receipt.Logs {
					l := *lg
					if removed {
						l.Removed = true
						deletedLogs = append(deletedLogs, &l)
					} else {
						rebirthLogs = append(rebirthLogs, &l)
					}
				}
			}
		}
	)

	// first reduce whoever is higher bound
	if oldBlock.NumberU64() > newBlock.NumberU64() {
		for ; oldBlock != nil && oldBlock.NumberU64() != newBlock.NumberU64(); oldBlock = bc.GetBlock(oldBlock.ParentHash(), oldBlock.NumberU64()-1) {
			oldChain = append(oldChain, oldBlock)
			deletedTxs = append(deletedTxs, oldBlock.Transactions()...)
			collectLogs(oldBlock.Hash(), true)
		}
	} else {
		for ; newBlock != nil && newBlock.NumberU64() != oldBlock.NumberU64(); newBlock = bc.GetBlock(newBlock.ParentHash(), newBlock.NumberU64()-1) {
			newChain = append(newChain, newBlock)
		}
	}

	if oldBlock == nil {
		return fmt.Errorf("Invalid old chain")
	}
	if newBlock == nil {
		return fmt.Errorf("Invalid new chain")
	}

	// find common ancestor
	for {
		if oldBlock.Hash() == newBlock.Hash() {
			commonBlock = oldBlock
			break
		}

		oldChain = append(oldChain, oldBlock)
		newChain = append(newChain, newBlock)
		deletedTxs = append(deletedTxs, oldBlock.Transactions()...)
		collectLogs(oldBlock.Hash(), true)

		oldBlock = bc.GetBlock(oldBlock.ParentHash(), oldBlock.NumberU64()-1)
		if oldBlock == nil {
			return fmt.Errorf("Invalid old chain")
		}
		newBlock = bc.GetBlock(newBlock.ParentHash(), newBlock.NumberU64()-1)
		if newBlock == nil {
			return fmt.Errorf("Invalid new chain")
		}
	}

	// Ensure the user sees large reorgs
	if len(oldChain) > 0 && len(newChain) > 0 {
		logFn := logging.Debug
		if len(oldChain) > 63 {
			logFn = logging.Warn
		}
		logFn("Chain split detected", "number", commonBlock.Number(), "hash", commonBlock.Hash().String(),
			"drop", len(oldChain), "dropfrom", oldChain[0].Hash().String(), "add", len(newChain), "addfrom", newChain[0].Hash().String())
	} else {
		logging.Error("Impossible reorg, please file an issue", "oldnum", oldBlock.Number(), "oldhash", oldBlock.Hash().String(), "newnum", newBlock.Number(), "newhash", newBlock.Hash().String())
	}

	for i := len(newChain) - 1; i >= 0; i-- {
		// insert the block in the canonical way, re-writing history
		bc.insert(newChain[i])

		// Collect reborn logs due to chain reorg
		collectLogs(newChain[i].Hash(), false)

		// write lookup entries for hash based transaction/receipt searches
		rawdb.WriteTxLookupEntries(bc.db, newChain[i])
		addedTxs = append(addedTxs, newChain[i].Transactions()...)
	}
	// calculate the difference between deleted and added transactions
	diff := types.TxDifference(deletedTxs, addedTxs)
	// When transactions get deleted from the database that means the
	// receipts that were created in the fork must also be deleted
	batch := bc.db.NewBatch()
	for _, tx := range diff {
		rawdb.DeleteTxLookupEntry(batch, tx.Hash())
	}
	batch.Write()

	go func() {
		if len(deletedLogs) > 0 {
			bc.rmLogsFeed.Send(RemovedLogsEvent{deletedLogs})
		}
		if len(rebirthLogs) > 0 {
			bc.logsFeed.Send(rebirthLogs)
		}
	}()
	return nil
}

// insert injects a new head block into the current block chain. This method
// assumes that the block is indeed a true head. It will also reset the head
// header and the head fast sync block to this very same block if they are older
// or if they are on a different side chain.
//
// Note, this function assumes that the `mu` mutex is held!
func (bc *BlockChain) insert(block *types.Block) {
	// Add the block to the canonical chain number scheme and mark as the head
	bc.hc.SetCurrentHeader(block.Header())
	bc.updateHeadBlock(block)
}

func (bc *BlockChain) updateHeadBlock(block *types.Block) {
	rawdb.WriteCanonicalHash(bc.db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(bc.db, block.Hash())

	bc.currentBlock.Store(block)

	//send to event bus
	evt := InsertBlockEvent{Block: block}
	go bc.eventMux.Post(evt)
}

// CurrentBlock retrieves the current head block of the canonical chain. The
// block is retrieved from the blockchain's internal cache.
func (bc *BlockChain) CurrentBlock() *types.Block {
	return bc.currentBlock.Load().(*types.Block)
}

// FullOriginBlockNumber returns the full-sync origin block number
func (bc *BlockChain) FullOriginBlockNumber() *big.Int {
	return new(big.Int).Set(bc.fullSyncOrigin)
}

// SetProcessor sets the processor required for making state modifications.
func (bc *BlockChain) SetProcessor(processor Processor) {
	bc.procmu.Lock()
	defer bc.procmu.Unlock()
	bc.processor = processor
}

// UpdateValidator sets the validator which is used to validate incoming blocks.
func (bc *BlockChain) SetValidator(validator Validator) {
	bc.procmu.Lock()
	defer bc.procmu.Unlock()
	bc.validator = validator
}

// Validator returns the current validator.
func (bc *BlockChain) Validator() Validator {
	bc.procmu.RLock()
	defer bc.procmu.RUnlock()
	return bc.validator
}

// Processor returns the current processor.
func (bc *BlockChain) Processor() Processor {
	bc.procmu.RLock()
	defer bc.procmu.RUnlock()
	return bc.processor
}

// GetBodyRLP retrieves a block body in RLP encoding from the database by hash,
// caching it if found.
func (bc *BlockChain) GetBodyRLP(hash common.Hash) rlp.RawValue {
	// Short circuit if the body's already in the cache, retrieve otherwise
	if cached, ok := bc.bodyRLPCache.Get(hash); ok {
		return cached.(rlp.RawValue)
	}
	number := bc.hc.GetBlockNumber(hash)
	if number == nil {
		return nil
	}
	body := rawdb.ReadBodyRLP(bc.db, hash, *number)
	if len(body) == 0 {
		return nil
	}
	// Cache the found body for next time and return
	bc.bodyRLPCache.Add(hash, body)
	return body
}

// HasBlock checks if a block is fully present in the database or not.
func (bc *BlockChain) HasBlock(hash common.Hash, number uint64) bool {
	if bc.blockCache.Contains(hash) {
		return true
	}
	return rawdb.HasBody(bc.db, hash, number)
}

// HasState checks if state trie is fully present in the database or not.
func (bc *BlockChain) HasState(hash common.Hash) bool {
	_, err := bc.stateCache.OpenTrie(hash)
	return err == nil
}

// HasBlockAndState checks if a block and associated state trie is fully present
// in the database or not, caching it if present.
func (bc *BlockChain) HasBlockAndState(hash common.Hash, number uint64) bool {
	// Check first that the block itself is known
	block := bc.GetBlock(hash, number)
	if block == nil {
		return false
	}
	return bc.HasState(block.Root())
}

func (bc *BlockChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	if block, ok := bc.blockCache.Get(hash); ok {
		return block.(*types.Block)
	}
	block := rawdb.ReadBlock(bc.db, hash, number)
	if block == nil {
		return nil
	}
	bc.blockCache.Add(block.Hash(), block)
	return block
}

func (bc *BlockChain) GetBlockNumber(hash common.Hash) *uint64 {
	if cached, ok := bc.numberCache.Get(hash); ok {
		number := cached.(uint64)
		return &number
	}
	number := rawdb.ReadHeaderNumber(bc.db, hash)
	if number != nil {
		bc.numberCache.Add(hash, *number)
	}
	return number
}

// GetBlockByNumber retrieves a block from the database by number, caching it
// (associated with its hash) if found.
func (bc *BlockChain) GetBlockByNumber(number uint64) *types.Block {
	hash := rawdb.ReadCanonicalHash(bc.db, number)
	if hash == (common.Hash{}) {
		return nil
	}
	return bc.GetBlock(hash, number)
}

// GetBlockByHash retrieves a block from the database by hash, caching it if found.
func (bc *BlockChain) GetBlockByHash(hash common.Hash) *types.Block {
	number := bc.hc.GetBlockNumber(hash)
	if number == nil {
		return nil
	}
	return bc.GetBlock(hash, *number)
}

// GetReceiptsByHash retrieves the receipts for all transactions in a given block.
func (bc *BlockChain) GetReceiptsByHash(hash common.Hash) types.Receipts {
	if receipts, ok := bc.receiptsCache.Get(hash); ok {
		return receipts.(types.Receipts)
	}
	number := rawdb.ReadHeaderNumber(bc.db, hash)
	if number == nil {
		return nil
	}
	receipts := rawdb.ReadReceipts(bc.db, hash, *number)
	if receipts == nil {
		return nil
	}
	bc.receiptsCache.Add(hash, receipts)
	return receipts
}

// CurrentHeader retrieves the current head header of the canonical chain. The
// header is retrieved from the HeaderChain's internal cache.
func (bc *BlockChain) CurrentHeader() *types.Header {
	return bc.hc.CurrentHeader()
}

func (bc *BlockChain) HasHeader(hash common.Hash, number uint64) bool {
	return bc.hc.HasHeader(hash, number)
}

// GetHeader retrieves a block header from the database by hash and number.
func (bc *BlockChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	return bc.hc.GetHeader(hash, number)
}

// GetHeaderByNumber retrieves a block header from the database by number.
func (bc *BlockChain) GetHeaderByNumber(number uint64) *types.Header {
	return bc.hc.GetHeaderByNumber(number)
}

// GetHeaderByHash retrieves a block header from the database by its hash.
func (bc *BlockChain) GetHeaderByHash(hash common.Hash) *types.Header {
	return bc.hc.GetHeaderByHash(hash)
}

// GetChtBuilder returns the CHTIndexer backend, for use of validating ACoCHT.
func (bc *BlockChain) GetChtBuilder() ChtBuilder {
	return bc.chtBackend
}

func (bc *BlockChain) GetAcReader() rawdb.AcReader {
	return bc.acReader
}

// Genesis retrieves the chain's genesis block.
func (bc *BlockChain) Genesis() *types.Block {
	return bc.genesisBlock
}

// StateAt returns a new mutable state based on the specific state root hash.
func (bc *BlockChain) StateAt(root, valRoot, stakingRoot common.Hash) (*state.StateDB, error) {
	//it's a new instance
	return state.New(root, valRoot, stakingRoot, bc.stateCache)
}

// State returns a new mutable state based on the current HEAD block.
func (bc *BlockChain) State() (*state.StateDB, error) {
	curr := bc.CurrentBlock()
	return bc.StateAt(curr.Root(), curr.ValRoot(), curr.StakingRoot())
}

//
func (bc *BlockChain) GetVldReader(valRoot common.Hash) (state.ValidatorReader, error) {
	reader, err := state.NewVldReader(valRoot, bc.stateCache)
	if err != nil && atomic.LoadInt32(&bc.onFastSyncing) == 1 {
		logging.Debug("try fetching validator trie from vldFetcher")
		err = bc.vldFetcher.FetchVldTrie(valRoot)
		if err == nil {
			reader, err = state.NewVldReader(valRoot, bc.stateCache)
		}
	}
	return reader, err
}

func (bc *BlockChain) Engine() consensus.Engine {
	return bc.engine
}

func (bc *BlockChain) GetLightStartHeader() *types.Header {
	return bc.hc.GetLightStartHeader()
}

func (bc *BlockChain) Reset() error {
	return bc.ResetWithGenesisBlock(bc.genesisBlock)
}

// ResetWithGenesisBlock purges the entire blockchain, restoring it to the
// specified genesis state.
func (bc *BlockChain) ResetWithGenesisBlock(genesis *types.Block) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	rawdb.WriteBlock(bc.db, genesis)

	bc.bodyCache.Purge()
	bc.bodyRLPCache.Purge()
	bc.blockCache.Purge()
	bc.numberCache.Purge()

	bc.genesisBlock = genesis
	bc.insert(bc.genesisBlock)

	bc.hc.SetGenesis(bc.genesisBlock.Header())

	bc.fullSyncOrigin = big.NewInt(0)

	return nil
}

// GetVMConfig returns the block chain VM config.
func (bc *BlockChain) GetVMConfig() *vm.LocalConfig {
	return &bc.vmConfig
}

func (bc *BlockChain) loadLastState() error {
	head := rawdb.ReadHeadBlockHash(bc.db)
	if head == (common.Hash{}) {
		// Corrupt or empty database, init from scratch
		logging.Warn("Empty database, resetting chain")
		return bc.Reset()
	}

	// Make sure the entire head block is available
	currentBlock := bc.GetBlockByHash(head)

	if currentBlock == nil {
		// Corrupt or empty database, init from scratch
		logging.Warn("Head block missing, resetting chain", "hash", head.String())
		return bc.Reset()
	}
	// Make sure the state associated with the block is available
	if _, err := state.New(currentBlock.Root(), currentBlock.ValRoot(), currentBlock.StakingRoot(), bc.stateCache); err != nil {
		// Dangling block without a state associated, init from scratch
		logging.Warn("Head state missing, repairing chain", "number", currentBlock.Number(), "hash", currentBlock.Hash().String())
		if err := bc.repair(&currentBlock); err != nil {
			return err
		}
	}

	// Everything seems to be fine, set as the head block
	bc.currentBlock.Store(currentBlock)
	bc.hc.SetCurrentHeader(currentBlock.Header())

	//load origin block number
	if originBlockNumber := rawdb.ReadFullOriginBlockNumber(bc.db); originBlockNumber.Cmp(big.NewInt(0)) > 0 {
		bc.fullSyncOrigin = new(big.Int).Set(originBlockNumber)
	}

	return nil
}

func (bc *BlockChain) SetHead(head uint64) error {
	logging.Warn("Rewinding blockchain", "target", head)

	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Rewind the header chain, deleting all block bodies until then
	delFn := func(db rawdb.DatabaseDeleter, hash common.Hash, num uint64) {
		rawdb.DeleteBody(db, hash, num)
	}

	targetBlock := bc.GetBlockByNumber(head)

	currentHeight := bc.CurrentHeader().Number.Uint64()

	batch := bc.db.NewBatch()

	for hdr := bc.CurrentHeader(); hdr != nil && hdr.Number.Uint64() > head; hdr = bc.CurrentHeader() {
		hash := hdr.Hash()
		num := hdr.Number.Uint64()

		logging.Info("SetHead deleting", "num", num, "hash", hash.String())

		delFn(batch, hash, num)

		rawdb.DeleteHeader(batch, hash, num)

		next := bc.GetBlock(hdr.ParentHash, num-1)

		bc.currentBlock.Store(next)
		bc.hc.SetCurrentHeader(next.Header())
	}

	for i := currentHeight; i > head; i-- {
		rawdb.DeleteCanonicalHash(bc.db, i)
	}

	batch.Write()

	bc.blockCache.Purge()
	bc.futureBlocks.Purge()
	bc.receiptsCache.Purge()

	bc.currentBlock.Store(targetBlock)
	bc.hc.SetCurrentHeader(targetBlock.Header())
	rawdb.WriteHeadBlockHash(bc.db, targetBlock.Hash())

	if head < bc.fullSyncOrigin.Uint64() {
		bc.fullSyncOrigin = new(big.Int).SetUint64(head)
		rawdb.WriteFullOriginBlockNumber(bc.db, bc.fullSyncOrigin)
	}

	return bc.loadLastState()
}

func (bc *BlockChain) repair(head **types.Block) error {
	for {
		// Abort if we've rewound to a head block that does have associated state
		if _, err := state.New((*head).Root(), (*head).ValRoot(), (*head).StakingRoot(), bc.stateCache); err == nil {
			logging.Info("Rewound blockchain to past state", "number", (*head).Number(), "hash", (*head).Hash().String())
			return nil
		}
		// Otherwise rewind one block and recheck state availability there
		block := bc.GetBlock((*head).ParentHash(), (*head).NumberU64()-1)
		if block == nil {
			return fmt.Errorf("missing block %d [%x]", (*head).NumberU64()-1, (*head).ParentHash())
		}
		*head = block
	}
}

func (bc *BlockChain) update() {
	futureTimer := time.NewTicker(5 * time.Second)
	defer futureTimer.Stop()
	for {
		select {
		case <-futureTimer.C:
			bc.procFutureBlocks()
		case <-bc.quit:
			return
		}
	}
}

func (bc *BlockChain) procFutureBlocks() {
	blocks := make([]*types.Block, 0, bc.futureBlocks.Len())
	for _, hash := range bc.futureBlocks.Keys() {
		if block, exist := bc.futureBlocks.Peek(hash); exist {
			blocks = append(blocks, block.(*types.Block))
		}
	}
	if len(blocks) > 0 {
		types.BlockBy(types.Number).Sort(blocks)

		// Insert one by one as chain insertion needs contiguous ancestry between blocks
		for i := range blocks {
			logging.Info("procFutureBlocks.", "number", blocks[i].NumberU64(), "hash", blocks[i].Hash().String())
			bc.InsertChain(blocks[i : i+1])
		}
	}
}

// BadBlocks returns a list of the last 'bad blocks' that the client has seen on the network
func (bc *BlockChain) BadBlocks() []*types.Block {
	blocks := make([]*types.Block, 0, bc.badBlocks.Len())
	for _, hash := range bc.badBlocks.Keys() {
		if blk, exist := bc.badBlocks.Peek(hash); exist {
			block := blk.(*types.Block)
			blocks = append(blocks, block)
		}
	}
	return blocks
}

// addBadBlock adds a bad block to the bad-block LRU cache
func (bc *BlockChain) addBadBlock(block *types.Block) {
	bc.badBlocks.Add(block.Hash(), block)
}

// StateTrieNode retrieves a blob of data associated with a trie node (or code hash)
// either from ephemeral in-memory cache, or from persistent storage.
func (bc *BlockChain) StateTrieNode(hash common.Hash) ([]byte, error) {
	return bc.stateCache.TrieDB().Node(hash)
}

// validator trie shares the same trie database with the state
func (bc *BlockChain) VldTrieNode(hash common.Hash) ([]byte, error) {
	return bc.stateCache.TrieDB().Node(hash)
}

func (bc *BlockChain) ChtTrieNode(hash common.Hash) ([]byte, error) {
	return bc.chtBackend.TrieDB().Node(hash)
}

func (bc *BlockChain) BltTrieNode(hash common.Hash) ([]byte, error) {
	return bc.bltBackend.TrieDB().Node(hash)
}

// TrieBackingDb returns the backing database of the specific kind of trie
func (bc *BlockChain) TrieBackingDb(kind types.TrieKind) youdb.Database {
	switch kind {
	case types.KindState:
		return bc.db
	case types.KindValidator:
		return bc.db
	case types.KindCht:
		return bc.chtBackend.TrieDB().DiskDB()
	case types.KindBlt:
		return bc.bltBackend.TrieDB().DiskDB()
	case types.KindStaking:
		return bc.db
	default:
		panic("not supported types.TrieKind")
	}
}

func (bc *BlockChain) UpdateTrustedCht(acHeader *types.Header) error {
	logging.Debug("UpdateTrustedCht", "chtRoot", hexutil.Encode(acHeader.ChtRoot))
	return bc.updateAcRoot(bc.chtIndexer, rawdb.StoreChtRoot, acHeader.ChtRoot, acHeader)
}

func (bc *BlockChain) UpdateTrustedBlt(acHeader *types.Header) error {
	return bc.updateAcRoot(bc.bltIndexer, rawdb.StoreBloomTrieRoot, acHeader.BltRoot, acHeader)
}

func (bc *BlockChain) updateAcRoot(indexer *ChainIndexer, store func(youdb.Putter, uint64, common.Hash, common.Hash) error, rootBytes []byte, acHeader *types.Header) error {
	num := acHeader.Number.Uint64()
	if len(rootBytes) == 0 || num%params.ACoCHTFrequency != 0 {
		return errors.New("invalid acHeader")
	}
	sec := num/params.ACoCHTFrequency - 1
	root := common.BytesToHash(rootBytes)
	// first store cht or blt root
	err := store(bc.db, sec, acHeader.ParentHash, root)
	if err != nil {
		return err
	}
	// then update indexer, if the cht or blt is not synced, it will got an error here.
	err = indexer.UpdateSection(sec, acHeader.ParentHash)
	return err
}

func (bc *BlockChain) GetHashFromCht(headerNum uint64) (common.Hash, error) {
	var hash common.Hash
	value, err := bc.chtBackend.GetValue(headerNum)
	if err == nil {
		hash = common.BytesToHash(value)
	}
	return hash, err
}

// reportBlock logs a bad block error.
func (bc *BlockChain) reportBlock(block *types.Block, receipts types.Receipts, err error) {
	bc.addBadBlock(block)

	var receiptString string
	for _, receipt := range receipts {
		receiptString += fmt.Sprintf("\t%v\n", receipt)
	}
	logging.Error(fmt.Sprintf(`
########## BAD BLOCK #########
NetworkId: %d
BAD BLOCK Number: %v Hash: 0x%x Coinbase: %s
%v

Error: %v
##############################
`, params.NetworkId(), block.Number(), block.Hash(), block.Coinbase().String(), receiptString, err))
}

func (bc *BlockChain) GetAncestor(hash common.Hash, number, ancestor uint64, maxNonCanonical *uint64) (common.Hash, uint64) {
	bc.chainMu.RLock()
	defer bc.chainMu.RUnlock()

	if ancestor > number {
		return common.Hash{}, 0
	}
	if ancestor == 1 {
		// in this case it is cheaper to just read the header
		if header := bc.GetHeader(hash, number); header != nil {
			return header.ParentHash, number - 1
		} else {
			return common.Hash{}, 0
		}
	}
	for ancestor != 0 {
		if rawdb.ReadCanonicalHash(bc.db, number) == hash {
			number -= ancestor
			return rawdb.ReadCanonicalHash(bc.db, number), number
		}
		if *maxNonCanonical == 0 {
			return common.Hash{}, 0
		}
		*maxNonCanonical--
		ancestor--
		header := bc.GetHeader(hash, number)
		if header == nil {
			return common.Hash{}, 0
		}
		hash = header.ParentHash
		number--
	}
	return hash, number
}

// SubscribeLogsEvent registers a subscription of []*types.Log.
func (bc *BlockChain) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
	return bc.scope.Track(bc.logsFeed.Subscribe(ch))
}

// SubscribeRemovedLogsEvent registers a subscription of RemovedLogsEvent.
func (bc *BlockChain) SubscribeRemovedLogsEvent(ch chan<- RemovedLogsEvent) event.Subscription {
	return bc.scope.Track(bc.rmLogsFeed.Subscribe(ch))
}

// SubscribeChainEvent registers a subscription of ChainEvent.
func (bc *BlockChain) SubscribeChainEvent(ch chan<- ChainEvent) event.Subscription {
	return bc.scope.Track(bc.chainFeed.Subscribe(ch))
}

// BloomStatus returns the bloom size and current stored sections.
func (bc *BlockChain) BloomStatus() (uint64, uint64) {
	sections, _, _ := bc.bltIndexer.Sections()
	return params.ACoCHTFrequency, sections
}

// InsertGuaranteedHeaderChain attempts to insert the given header chain into the local
// chain, the header chain here MUST be already guaranteed by cht or other verification.
// If an error is returned, it will return the index number of the failing header
// as well an error describing what went wrong.
func (bc *BlockChain) InsertGuaranteedHeaderChain(chain []*types.Header) (int, error) {
	start := time.Now()
	// check that the YOUChain protocol version state is following the rules
	i, err := bc.VerifyYouVersionState2(chain)
	if err != nil {
		wrapErr := fmt.Errorf("VerifyYouVersionState failed, index=%d versionState=%s err=%v", i, chain[i].VersionStateString(), err)
		logging.Warn(wrapErr.Error())
		return i, wrapErr
	}

	seals := make([]bool, len(chain))
	if i, err := bc.hc.ValidateHeaderChain(chain, seals); err != nil {
		return i, err
	}

	// Make sure only one thread manipulates the chain at once
	bc.chainMu.Lock()
	defer bc.chainMu.Unlock()
	bc.wg.Add(1)
	defer bc.wg.Done()

	whFunc := func(header *types.Header) error {
		err := bc.hc.WriteHeader(header)
		return err
	}
	if i, err := bc.hc.InsertHeaderChain(chain, whFunc, start); err != nil {
		return i, err
	}

	return 0, nil
}

// InsertHeaderChain attempts to insert the given header chain into the local chain.
// The header which number is multiple of seedLookBack will be verifying seal, but
// the others will not. If an error is returned, it will return the index number
// of the failing header as well an error describing what went wrong.
func (bc *BlockChain) InsertHeaderChain(chain []*types.Header) (int, error) {
	ln := len(chain)
	if ln == 0 {
		return 0, nil
	}

	defer bc.wrapWithFastSyncingFlag()()

	start := time.Now()
	// check that the YOUChain protocol version state is following the rules
	i, err := bc.VerifyYouVersionState2(chain)
	if err != nil {
		wrapErr := fmt.Errorf("VerifyYouVersionState failed, index=%d versionState=%s err=%v", i, chain[i].VersionStateString(), err)
		logging.Warn(wrapErr.Error())
		return i, wrapErr
	}

	seedLookBack, _ := bc.UconLookBackParams()
	seals := initSealForLeapfrogVerify(chain[0].Number.Uint64(), seedLookBack, ln)
	if i, err := bc.hc.ValidateHeaderChain(chain, seals); err != nil {
		return i, err
	}

	// Make sure only one thread manipulates the chain at once
	bc.chainMu.Lock()
	defer bc.chainMu.Unlock()
	bc.wg.Add(1)
	defer bc.wg.Done()

	whFunc := func(header *types.Header) error {
		err := bc.hc.WriteHeader(header)
		return err
	}
	if i, err := bc.hc.InsertHeaderChain(chain, whFunc, start); err != nil {
		return i, err
	}

	return 0, nil
}

// just update the votes' info of the existed header, do not change the header number and hash
func (bc *BlockChain) UpdateExistedHeader(header *types.Header) {
	//logging.Info("UpdateExistedHeader.", "number", header.Number, "hash", header.Hash().String())
	// Make sure only one thread manipulates the chain at once
	bc.chainMu.Lock()
	defer bc.chainMu.Unlock()
	bc.wg.Add(1)
	defer bc.wg.Done()

	rawdb.WriteHeader(bc.db, header)

	bc.hc.headerCache.Remove(header.Hash())
	bc.hc.headerCache.Add(header.Hash(), header)
}

func (bc *BlockChain) wrapWithFastSyncingFlag() func() {
	atomic.StoreInt32(&bc.onFastSyncing, 1)
	return func() {
		atomic.StoreInt32(&bc.onFastSyncing, 0)
	}
}

func (bc *BlockChain) updateFullOrigin(lastFast *big.Int) {
	bc.fullSyncOrigin = new(big.Int).Add(lastFast, big.NewInt(1))
	rawdb.WriteFullOriginBlockNumber(bc.db, bc.fullSyncOrigin)
}

func initSealForLeapfrogVerify(startNum, freq uint64, ln int) []bool {
	seedLookBack := int(freq)
	seals := make([]bool, ln)
	sealIndex := int(startNum % freq)
	if sealIndex != 0 {
		sealIndex = seedLookBack - sealIndex
	}
	for sealIndex < ln {
		seals[sealIndex] = true
		sealIndex += seedLookBack
	}
	//verify seal for the all rest
	if sealIndex < seedLookBack {
		sealIndex = -1
	} else {
		sealIndex -= seedLookBack
	}
	for sealIndex++; sealIndex < ln; sealIndex++ {
		seals[sealIndex] = true
	}
	return seals
}

func (bc *BlockChain) SetVldFetcher(fetcher VldFetcher) {
	bc.vldFetcher = fetcher
}

// InsertReceiptChain attempts to complete an already existing header chain with
// transaction and receipt data.
func (bc *BlockChain) InsertReceiptChain(blockChain types.Blocks, receiptChain []types.Receipts, postEvent bool) (int, error) {
	// We don't require the chainMu here since we want to maximize the
	// concurrency of header insertion and receipt insertion.
	bc.wg.Add(1)
	defer bc.wg.Done()

	// Do a sanity check that the provided chain is actually ordered and linked
	for i := 1; i < len(blockChain); i++ {
		if blockChain[i].NumberU64() != blockChain[i-1].NumberU64()+1 || blockChain[i].ParentHash() != blockChain[i-1].Hash() {
			logging.Error("Non contiguous receipt insert", "number", blockChain[i].Number(), "hash", blockChain[i].Hash(), "parent", blockChain[i].ParentHash(),
				"prevnumber", blockChain[i-1].Number(), "prevhash", blockChain[i-1].Hash())
			return 0, fmt.Errorf("non contiguous insert: item %d is #%d [%x…], item %d is #%d [%x…] (parent [%x…])", i-1, blockChain[i-1].NumberU64(),
				blockChain[i-1].Hash().Bytes()[:4], i, blockChain[i].NumberU64(), blockChain[i].Hash().Bytes()[:4], blockChain[i].ParentHash().Bytes()[:4])
		}
	}

	var (
		stats = struct{ processed, ignored int32 }{}
		start = time.Now()
		size  = 0
	)

	// writeLive writes blockchain and corresponding receipt chain into active store.
	writeLive := func(blockChain types.Blocks, receiptChain []types.Receipts) (int, error) {
		batch := bc.db.NewBatch()
		for i, block := range blockChain {
			// Short circuit insertion if shutting down or processing failed
			if atomic.LoadInt32(&bc.procInterrupt) == 1 {
				return 0, errInsertionInterrupted
			}
			// Short circuit if the owner header is unknown
			if !bc.HasHeader(block.Hash(), block.NumberU64()) {
				return i, fmt.Errorf("containing header #%d [%x…] unknown", block.Number(), block.Hash().Bytes()[:4])
			}
			if bc.HasBlock(block.Hash(), block.NumberU64()) {
				stats.ignored++
				continue
			}
			// Write all the data out into the database
			rawdb.WriteBody(batch, block.Hash(), block.NumberU64(), block.Body())
			rawdb.WriteReceipts(batch, block.Hash(), block.NumberU64(), receiptChain[i])
			rawdb.WriteTxLookupEntries(batch, block)

			stats.processed++
			if batch.ValueSize() >= youdb.IdealBatchSize {
				if err := batch.Write(); err != nil {
					return 0, err
				}
				size += batch.ValueSize()
				batch.Reset()
			}
		}
		if batch.ValueSize() > 0 {
			size += batch.ValueSize()
			if err := batch.Write(); err != nil {
				return 0, err
			}
		}
		return 0, nil
	}

	if n, err := writeLive(blockChain, receiptChain); err != nil {
		if err == errInsertionInterrupted {
			return 0, nil
		}
		return n, err
	}

	head := blockChain[len(blockChain)-1]
	context := []interface{}{
		"count", stats.processed, "elapsed", common.PrettyDuration(time.Since(start)),
		"number", head.Number(), "hash", head.Hash(), "age", common.PrettyAge(time.Unix(int64(head.Time()), 0)),
		"size", common.StorageSize(size),
	}
	if stats.ignored > 0 {
		context = append(context, []interface{}{"ignored", stats.ignored}...)
	}
	logging.Info("Imported new block receipts", context...)

	bc.updateHeadBlock(head)
	bc.updateFullOrigin(head.Number())
	if postEvent {
		events := make([]interface{}, 1)
		events[0] = ChainHeadEvent{head}
		bc.PostChainEvents(events, nil)
	}

	return 0, nil
}

func (bc *BlockChain) IsLight() bool {
	return bc.nodeType == params.LightNode
}

// pruneOldData prunes old block data for light-client
func (bc *BlockChain) pruneOldData() {
	pruneFunc := func() {
		head := bc.CurrentHeader().Number.Uint64()
		start := bc.GetLightStartHeader().Number.Uint64()
		if start == 0 {
			start = 1 // Genesis can't be deleted!
		}
		if head > start && head-start > 2*params.ACoCHTFrequency {
			defer func(oldstart uint64, st time.Time) {
				newstart := bc.GetLightStartHeader().Number.Uint64()
				logging.Info("pruneOldData", "oldLightStart", oldstart, "newLightStart", newstart, "elapse", time.Since(st))
			}(start, time.Now())

			logging.Trace("try to prune old data", "currentLightStart", start, "currentHead", head)
			distance := head - 2*params.ACoCHTFrequency - start
			sec := int(distance / maxSinglePruneSize)
			for i := 0; i < sec; i++ {
				end := start + maxSinglePruneSize
				err := bc.doPrune(start, end)
				if err != nil {
					logging.Error("prune data failed", "from", start, "to", end, "err", err)
					return
				}
				start = end
			}
		}
	}

	pruneFunc()
	ticker := time.NewTicker(pruneIntervalM * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pruneFunc()
		case <-bc.quit:
			return
		}
	}
}

func (bc *BlockChain) doPrune(start, end uint64) error {
	newStartHeader := bc.hc.GetHeaderByNumber(end)
	if newStartHeader == nil {
		return fmt.Errorf("SHOULD NOT HAPPENED! can't get header, number=%d", end)
	}
	bc.chainMu.Lock()
	defer bc.chainMu.Unlock()
	bc.wg.Add(1)
	defer bc.wg.Done()

	batch := bc.db.NewBatch()
	rawdb.WriteLightStartHeaderHash(batch, newStartHeader.Hash())
	bc.hc.storeLightStartHeader(newStartHeader)
	for num := start; num < end; num++ {
		header := bc.hc.GetHeaderByNumber(num)
		if header != nil {
			hash := header.Hash()
			if rawdb.HasBody(bc.db, hash, num) {
				rawdb.DeleteBlock(batch, hash, num)
			} else {
				rawdb.DeleteHeader(batch, hash, num)
			}
		}
	}
	err := batch.Write()
	return err
}
