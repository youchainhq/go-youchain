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

package downloader

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core/rawdb"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/youdb"
)

var (
	MaxBlockFetch     = 128         // Amount of blocks to be fetched per retrieval request
	MaxHeaderFetch    = 192         // Amount of block headers to be fetched per retrieval request
	MaxSkeletonSize   = uint64(128) // Number of header fetches to need for a skeleton assembly
	MaxReceiptFetch   = 256         // Amount of transaction receipts to allow fetching per request
	MaxTrieNodeFetch  = 384         // Amount of trie node values to allow fetching per request
	maxHeadersProcess = 2048        // Number of header download results to import at once into the chain
	maxQueuedHeaders  = 32 * 1024   // Maximum number of headers to queue for import (DOS protection)
	maxResultsProcess = 2048        // Number of content download results to import at once into the chain

	rttMinEstimate    = 2 * time.Second  // Minimum round-trip time to target for download requests
	rttMaxEstimate    = 20 * time.Second // Maximum round-trip time to target for download requests
	rttMinConfidence  = 0.1              // Worse confidence factor in our estimated RTT value
	ttlScaling        = 3                // Constant scaling factor for RTT -> TTL conversion
	ttlLimit          = time.Minute      // Maximum TTL allowance to prevent reaching crazy timeouts
	fsHeaderContCheck = 1 * time.Second  // Time interval to check for header continuations during state download

	qosTuningPeers   = 5    // Number of peers to tune based on (best peers)
	qosConfidenceCap = 10   // Number of peers above which not to modify RTT confidence
	qosTuningImpact  = 0.25 // Impact that a new tuning target has on the previous value
)

const (
	maxForkBlocksCount = 500
)
const (
	FastLightDone uint8 = iota
	FastUndone
	LightUndone
)

var (
	errBusy                    = errors.New("busy")
	errBadPeer                 = errors.New("action from bad peer ignored")
	errStallingPeer            = errors.New("peer is stalling")
	errTimeout                 = errors.New("timeout")
	errInvalidChain            = errors.New("retrieved hash chain is invalid")
	errNoSyncActive            = errors.New("no sync active")
	errCanceled                = errors.New("syncing canceled (requested)")
	errInvalidBody             = errors.New("retrieved block body is invalid")
	errInvalidReceipt          = errors.New("retrieved receipt is invalid")
	errNoPeers                 = errors.New("no peers to keep download active")
	errPeersUnavailable        = errors.New("no peers available or all tried for download")
	errUnknownPeer             = errors.New("peer is unknown or unhealthy")
	errEmptyHeaderSet          = errors.New("empty header set by peer")
	errInvalidAncestor         = errors.New("retrieved ancestor is invalid")
	errCancelHeaderFetch       = errors.New("block header download canceled (requested)")
	errCancelTrieFetch         = errors.New("trie data download canceled (requested)")
	errCancelContentProcessing = errors.New("content processing canceled (requested)")
)

// LightChain encapsulates functions required to synchronise a light chain.
type LightChain interface {
	// CurrentHeader retrieves the head header from the local chain.
	CurrentHeader() *types.Header
	// GetHeaderByNumber retrieves a header by number from the local chain
	GetHeaderByNumber(number uint64) *types.Header
	// GetHeaderByHash retrieves a header from the local chain.
	GetHeaderByHash(common.Hash) *types.Header
	// GetLightStartHeader retrieves the start header of a light-client
	GetLightStartHeader() *types.Header

	// IsUcon returns whether the consensus is Ucon
	IsUcon() bool
	UconLookBackParams() (seedLookBack, stakeLookBack uint64)

	// TrieBackingDb returns the backing database of the specific kind of trie
	TrieBackingDb(kind types.TrieKind) youdb.Database

	// VerifyAcHeader verifies the header using CHT certificates, mainly for fast or light sync
	VerifyAcHeader(header *types.Header, verifiedAcParents []*types.Header) error

	// UpdateTrustedCht update the CHT indexer when the trie which is represented by acHeader.ChtRoot is fetched.
	UpdateTrustedCht(acHeader *types.Header) error

	// UpdateTrustedBlt update the BLT indexer when the trie which is represented by acHeader.BltRoot is fetched.
	UpdateTrustedBlt(acHeader *types.Header) error

	// GetHashFromCht gets the header hash from CHT.
	GetHashFromCht(headerNum uint64) (common.Hash, error)

	// InsertGuaranteedHeaderChain attempts to insert the given header chain into the local
	// chain, the header chain here MUST be already guaranteed by cht or other verification.
	InsertGuaranteedHeaderChain(chain []*types.Header) (int, error)

	// InsertHeaderChain attempts to insert the given (unverified) header chain into the local chain.
	InsertHeaderChain(chain []*types.Header) (int, error)
}

// BlockChain encapsulates functions required to sync a (full or fast) blockchain.
type BlockChain interface {
	LightChain
	// HasBlock verifies a block's presence in the local chain.
	HasBlock(common.Hash, uint64) bool

	// CurrentBlock retrieves the head block from the local chain.
	CurrentBlock() *types.Block

	// InsertChain inserts a batch of blocks into the local chain.
	InsertChain(types.Blocks) error

	// InsertReceiptChain inserts a batch of receipts into the local chain.
	// the bool parameter indicates where to post the ChainHeadEvent or not
	InsertReceiptChain(types.Blocks, []types.Receipts, bool) (int, error)
}

type Downloader struct {
	// WARNING: The `rttEstimate`, `rttConfidence` and `latestValidAcNum` fields are accessed atomically.
	// On 32 bit platforms, only 64-bit aligned fields can be atomic. The struct is
	// guaranteed to be so aligned, so take advantage of that. For more information,
	// see https://golang.org/pkg/sync/atomic/#pkg-note-BUG.
	rttEstimate      uint64 // Round trip time to target for download requests
	rttConfidence    uint64 // Confidence in the estimated RTT (unit: millionths to allow atomic ops)
	latestValidAcNum uint64 // Latest valid acHeader number

	mode SyncMode // Synchronisation mode defining the strategy used (per sync cycle)

	lightchain LightChain
	blockchain BlockChain
	chainDb    youdb.Database

	// Callbacks
	peers    *PeerSet
	dropPeer peerDropFn // Drops a peer for misbehaving

	// Status
	synchronising int32
	notified      int32
	//committed       int32

	// for trieFetcher
	trieSyncStart chan *trieSync // Channel for stating a trie sync task
	trackTrieReq  chan *trieReq
	trieCh        chan dataPack // Channel receiving inbound node trie data

	//Statistics
	syncStatsChainOrigin uint64 // Origin block number where syncing started at
	syncStatsChainHeight uint64 // Highest block number known when syncing started
	syncStatsState       stateSyncStats
	syncStatsLock        sync.RWMutex // Lock protecting the sync stats fields

	// Cancellation and termination
	cancelPeer string         // Identifier of the peer currently being used as the master (cancel on drop)
	cancelCh   chan struct{}  // Channel to cancel mid-flight syncs
	cancelLock sync.RWMutex   // Lock to protect the cancel channel and peer in delivers
	cancelWg   sync.WaitGroup // Make sure all fetcher goroutines have exited.

	quitCh   chan struct{} // Quit channel to signal termination
	quitLock sync.RWMutex  // Lock to prevent double closes

	mux *event.TypeMux // Event multiplexer to announce sync operation events

	// Channels
	bodyWakeCh    chan bool            // Channel to signal the block body fetcher of new tasks
	receiptWakeCh chan bool            // Channel to signal the receipt fetcher of new tasks
	headerCh      chan dataPack        // Channel receiving inbound block headers
	bodyCh        chan dataPack        // Channel receiving inbound block bodies
	receiptCh     chan dataPack        // Channel receiving inbound receipts
	headerProcCh  chan []*types.Header // Channel to feed the header processor new tasks

	insertedHeaderCh chan []*types.Header // Channel to feed the light sync processor the inserted headers.

	queue *queue // Scheduler for selecting the hashes to download

	// ACoCHT relative
	acfilter           *acFilter
	acHeaderCh         chan dataPack        // Channel receiving inbound ac headers
	acHeaderProcCh     chan []*types.Header // Channel to feed the acHeader processor new tasks
	verifiedAcHeaderCh chan *types.Header   // Channel to feed fetchHeaders new ac header,and use a nil value to signal fetchHeaders start fetching (the rest) headers normally.
	isUcon             bool                 // Whether the consensus engine is ucon
	leapfrogStep       uint64               // Leapfrog validation step, equals to seedLookBack
	stakeLookBack      uint64
}

func New(chain BlockChain, lightChain LightChain, chainDb youdb.Database, dropPeer peerDropFn, mux *event.TypeMux) *Downloader {
	if lightChain == nil {
		lightChain = chain
	}
	dl := &Downloader{
		blockchain:         chain,
		lightchain:         lightChain,
		chainDb:            chainDb,
		peers:              newPeerSet(),
		dropPeer:           dropPeer,
		quitCh:             make(chan struct{}),
		mux:                mux,
		rttEstimate:        uint64(rttMaxEstimate),
		rttConfidence:      uint64(1000000),
		bodyWakeCh:         make(chan bool, 1),
		receiptWakeCh:      make(chan bool, 1),
		headerCh:           make(chan dataPack, 1),
		bodyCh:             make(chan dataPack, 1),
		receiptCh:          make(chan dataPack, 1),
		headerProcCh:       make(chan []*types.Header, 1),
		insertedHeaderCh:   make(chan []*types.Header, 1),
		trieCh:             make(chan dataPack),
		queue:              newQueue(),
		acfilter:           newAcFilter(),
		acHeaderCh:         make(chan dataPack, 1),
		acHeaderProcCh:     make(chan []*types.Header, 1),
		verifiedAcHeaderCh: make(chan *types.Header, 1),
		trieSyncStart:      make(chan *trieSync),
		trackTrieReq:       make(chan *trieReq),
		syncStatsState: stateSyncStats{
			processed: rawdb.ReadFastTrieProgress(chainDb),
		},
		isUcon: chain.IsUcon(),
	}
	if dl.isUcon {
		dl.leapfrogStep, dl.stakeLookBack = dl.lightchain.UconLookBackParams()
	}

	go dl.qosTuner()
	go dl.trieFetcher()
	return dl
}

func (d *Downloader) Synchronising() bool {
	return atomic.LoadInt32(&d.synchronising) > 0
}

// Progress retrieves the synchronisation boundaries, specifically the origin
// block where synchronisation started at (may have failed/suspended); the block
// or header sync is currently at; and the latest known block which the sync targets.
//
// In addition, during the state download phase of fast synchronisation the number
// of processed and the total number of known nodes are also returned. Otherwise
// these are zero.
func (d *Downloader) Progress() SyncProgress {
	// Lock the current stats and return the progress
	d.syncStatsLock.RLock()
	defer d.syncStatsLock.RUnlock()

	current := uint64(0)
	switch {
	case d.blockchain != nil && d.mode == FullSync:
		current = d.blockchain.CurrentBlock().NumberU64()
	case d.blockchain != nil && d.mode == FastSync:
		current = d.blockchain.CurrentBlock().NumberU64()
	case d.mode == LightSync:
		current = d.lightchain.CurrentHeader().Number.Uint64()
	default:
		logging.Error("Unknown downloader chain/mode combo", "full", d.blockchain != nil, "mode", d.mode)
	}
	return SyncProgress{
		StartingBlock: d.syncStatsChainOrigin,
		CurrentBlock:  current,
		HighestBlock:  d.syncStatsChainHeight,
		PulledStates:  d.syncStatsState.processed,
		KnownStates:   d.syncStatsState.processed + d.syncStatsState.pending,
	}
}

// Synchronise tries to sync up our local block chain with a remote peer, both
// adding various sanity checks as well as wrapping it with various log entries.
func (d *Downloader) Synchronise(id string, peerNumber *big.Int, mode SyncMode) error {
	err := d.synchronise(id, peerNumber, mode)
	switch err {
	case nil:
	case errUnknownPeer:
		logging.Error("Synchronise", "pid", id, "err", errUnknownPeer)
	case errBusy:
		logging.Warn("Synchronise", "err", err)
	case errTimeout, errBadPeer, errInvalidChain:
		logging.Warn("Synchronise failed, dropping peer", "pid", id, "err", err)
		d.dropPeer(id)

	default:
		logging.Warn("Synchronise failed", "err", err)
	}
	return err
}

// synchronise will select the peer and use it for synchronising. If an empty string is given
// it will use the best peer possible and synchronize if its TD is higher than our own. If any of the
// checks fail an error will be returned. This method is synchronous
func (d *Downloader) synchronise(id string, peerNumber *big.Int, mode SyncMode) error {
	// Make sure only one goroutine is ever allowed past this point at once
	if !atomic.CompareAndSwapInt32(&d.synchronising, 0, 1) {
		logging.Warn("downloader synchronise peer busy", "err", errBusy, "pid", id)
		return errBusy
	}
	defer func() {
		atomic.StoreInt32(&d.synchronising, 0)
		logging.Trace("downloader set synchronising = 0", "pid", id)
	}()

	// Post a user notification of the sync (only once per session)
	if atomic.CompareAndSwapInt32(&d.notified, 0, 1) {
		logging.Trace("Set notified to 1 ok", "mode", mode.String())
	}
	logging.Info("Block synchronisation started", "mode", mode.String(), "pid", id, "peer number", peerNumber)
	// init latestValidAcNum
	atomic.StoreUint64(&d.latestValidAcNum, 0)
	// Reset the queue, peer set and wake channels to clean any internal leftover state
	d.queue.Reset()
	d.peers.Reset()
	for _, ch := range []chan bool{d.bodyWakeCh, d.receiptWakeCh} {
		select {
		case <-ch:
		default:
		}
	}
	for _, ch := range []chan dataPack{d.headerCh, d.trieCh, d.bodyCh, d.receiptCh, d.acHeaderCh} {
		select {
		case <-ch:
		default:
		}
	}
	for _, ch := range []chan []*types.Header{d.headerProcCh, d.acHeaderProcCh, d.insertedHeaderCh} {
		for empty := false; !empty; {
			select {
			case <-ch:
			default:
				empty = true
			}
		}
	}
	for empty := false; !empty; {
		select {
		case <-d.verifiedAcHeaderCh:
		default:
			empty = true
		}
	}
	// Create cancel channel for aborting mid-flight and mark the master peer
	d.cancelLock.Lock()
	d.cancelCh = make(chan struct{})
	d.cancelPeer = id
	d.cancelLock.Unlock()

	defer d.Cancel() // No matter what, we can't leave the cancel channel open

	if d.isUcon {
		d.mode = mode
	} else {
		d.mode = FullSync //Currently only a chain based on Ucon is supporting FastSync and LightSync.
	}

	p := d.peers.Peer(id)
	if p == nil {
		logging.Error("synchronise errUnknownPeer")
		return errUnknownPeer
	}
	return d.syncWithPeer(p, peerNumber)
}

// syncWithPeer starts a block synchronization based on the hash chain from the
// specified peer and head hash.
func (d *Downloader) syncWithPeer(p *peerConnection, peerNumber *big.Int) (err error) {
	start := time.Now()
	logging.Info("syncWithPeer post StartEvent", "pid", p.id)
	d.mux.Post(StartEvent{}) // signal to stop miner
	defer func() {
		// reset on error
		logging.Info("syncWithPeer sync result", "err", err)
		if err != nil {
			d.mux.Post(FailedEvent{err})
		} else {
			d.mux.Post(DoneEvent{d.lightchain.CurrentHeader()})
		}
	}()

	latestHeader, err := d.fetchHeight(p) //fetch the remote height
	if err != nil {
		logging.Info("syncWithPeer", "err", err)
		return err
	}
	height := latestHeader.Number.Uint64()
	logging.Trace("syncWithPeer remote", "height", height)

	origin, err := d.findAncestor(p, latestHeader) // find common ancestor
	if err != nil {
		return err
	}
	if height <= origin {
		// This may happens because the `fetcher/fetcher.go` is also keep tracking the latest blocks
		// when previous sync is done (the local chain has catching up the chain height).
		return nil
	}
	logging.Trace("syncWithPeer ancestor", "origin", origin)

	d.syncStatsLock.Lock()
	if d.syncStatsChainHeight <= origin || d.syncStatsChainOrigin > origin {
		d.syncStatsChainOrigin = origin
	}
	d.syncStatsChainHeight = height
	d.syncStatsLock.Unlock()

	// check mini distance for fast sync
	if (d.mode == FastSync || d.mode == LightSync) && (height-origin) < 2*d.stakeLookBack {
		if rawdb.ReadFastSyncUndoneFlag(d.chainDb) != LightUndone {
			// The previous LightSync must be fully succeed
			// before we turn to a FullSync.
			// The reason is: we need a full parent block for the FullSync,
			// which won't be exists when a LightSync is not fully succeed;
			// Still it's difficult to repair this case in the `prepareForFullSync`,
			// cause the FullSync no need to sync the receipts.
			d.mode = FullSync
		}
	}
	logging.Info("syncWithPeer", "mode", d.mode.String(), "origin", origin, "height", height)

	// Initiate the sync using a concurrent header and content retrieval algorithm
	d.queue.Prepare(origin+1, d.mode)

	fetchers := make([]func() error, 0, 8)
	firstNoneAc := origin + 1
	fetchers = append(fetchers, func() error { return d.fetchHeaders(p, origin+1, height, firstNoneAc) })
	fetchers = append(fetchers, func() error { return d.processHeaders(origin + 1) })
	fetchers = append(fetchers, func() error { return d.fetchBodies() })
	// Receipts are retrieved during fastSync or LightSync,
	// BUT it's still needed for fullSync to dry up receiptWakeCh.
	fetchers = append(fetchers, func() error { return d.fetchReceipts() })
	if d.mode == FastSync || d.mode == LightSync {
		// (For caravel) FastSync:
		// 1. From the `origin`, download blocks at the frequency of `ACoCHTFrequency`,
		// verify the `Certificates`, until the lastAcNodeBlock (which is `lastSection*ACoCHTFrequency`);
		// 		1) Initially fastStart=origin;
		// 		2) Process the `acNodes` one by one, that is: download the acNode[i],
		// 		then use the seed of acNode[i-2] and the stake of acNode[i-1]
		// 		to verify acNode[i];
		//		3) If the verification pass, download the CHT,
		//		and the validator trie of the acNode[i];
		//		4) Download the blocks between the fastStart and the acNode[i] asynchronously;
		//		During this process, get block hashes from the CHT to build skeleton,
		//		and then fill up the skeleton, with a sanity check we can
		//		insert these blocks directly into the canonical chain.
		//
		//		5) fastStart=acNode[i], i++, continue 2).
		// 2. After the lastAcNodeBlock, start the leapfrog synchronise by step `c`
		// (which is equal to the SeedLookBack), and finally do the full-sync
		// for the last few blocks( with the synchronised validator tries,
		// not from locally build)
		lastSection := height / params.ACoCHTFrequency
		startSection := origin/params.ACoCHTFrequency + 1
		if startSection <= lastSection {
			firstNoneAc = lastSection*params.ACoCHTFrequency + 1
			fetchers = append(fetchers, func() error { return d.fetchAcHeaders(p, startSection, lastSection) })
			fetchers = append(fetchers, func() error { return d.processAcHeaders(origin + 1) })
		} else {
			// no need to fetch acHeader, signal to start fetching the rest headers
			d.verifiedAcHeaderCh <- nil
		}
		if d.mode == FastSync {
			fetchers = append(fetchers, func() error { return d.processFastSyncContent(latestHeader) })
		} else {
			fetchers = append(fetchers, func() error { return d.processLightSync(latestHeader) })
		}
	}

	if d.mode == FullSync {
		fetchers = append(fetchers, func() error { return d.prepareForFullSync(origin + 1) })
		fetchers = append(fetchers, func() error { return d.processFullSyncContent(origin + 1) })
	}

	defer func() {
		var currHeight uint64
		if d.mode == LightSync {
			currHeight = d.lightchain.CurrentHeader().Number.Uint64()
		} else {
			currHeight = d.blockchain.CurrentHeader().Number.Uint64()
		}
		logging.Info("syncWithPeer end", "mode", d.mode.String(), "from", origin+1, "currentHeight", currHeight, "elapse", time.Since(start).String())
	}()
	return d.spawnSync(fetchers)
}

// spawnSync runs d.process and all given fetcher functions to completion in
// separate goroutines, returning the first error that appears.
func (d *Downloader) spawnSync(fetchers []func() error) error {
	logging.Trace("spawnSync", "fetchersCount", len(fetchers))
	errc := make(chan error, len(fetchers))
	d.cancelWg.Add(len(fetchers))
	for _, fn := range fetchers {
		fn := fn
		go func() { defer d.cancelWg.Done(); errc <- fn() }()
	}
	// Wait for the first error, then terminate the others.
	var err error
	for i := 0; i < len(fetchers); i++ {
		if i == len(fetchers)-1 {
			logging.Debug("close queue")
			// Close the queue when all fetchers have exited.
			// This will cause the block processor to end when
			// it has processed the queue.
			d.queue.Close()
		}
		logging.Trace("spawnSync waiting fetcher errc", "i", i)
		if err = <-errc; err != nil {
			break
		}
		logging.Trace("spawnSync waiting fetcher errc done, no error", "i", i)
	}
	d.queue.Close()
	d.Cancel()
	return err
}

// fetchAcHeaders downloads and verifies AcHeaders,
// should only be called when the consensus is Ucon and sync mode is not FullSync.
func (d *Downloader) fetchAcHeaders(p *peerConnection, startSection, endSection uint64) error {
	if !p.SetHeadersBusy() {
		return errAlreadyFetching
	}

	var delivered int // count of headers delivered
	// set headers idle for the main peer
	defer func() {
		p.SetHeadersIdle(delivered)
	}()

	if d.acfilter.Add(p.id) {
		defer d.acfilter.Remove(p.id)
	} else {
		return errors.New("add to acFilter failed")
	}
	var request time.Time // time of the last fetch request
	ttl := d.requestTTL()
	timeout := time.After(ttl)
	lightHeader := d.mode == LightSync
	getHeaders := func(startSec uint64) {
		request = time.Now()
		size := MaxHeaderFetch
		if int(endSection-startSec) < size {
			size = int(endSection - startSec + 1)
		}
		p.log.Trace("Fetching AcHeaders", "startSec", startSec, "size", size)
		go p.peer.RequestHeadersByNumber(startSec*params.ACoCHTFrequency, size, int(params.ACoCHTFrequency-1), false, lightHeader)
	}
	getHeaders(startSection)

	for {
		select {
		case <-d.cancelCh:
			return errCanceled

		case packet := <-d.acHeaderCh:
			// Make sure the active peer is giving us the AcBlock headers
			if packet.PeerId() != p.id {
				logging.Debug("Received AcHeaders from incorrect peer", "peer", packet.PeerId())
				break
			}
			headerReqTimer.UpdateSince(request)
			if packet.Items() == 0 {
				//fetch ac headers done
				select {
				case d.acHeaderProcCh <- nil:
					return nil
				case <-d.cancelCh:
					return errCanceled
				}
			}
			//else, we got headers
			headers := packet.(*headerPack).headers
			select {
			case d.acHeaderProcCh <- headers:
				delivered += len(headers)
				lastSet := headers[len(headers)-1].Number.Uint64() / params.ACoCHTFrequency
				startSec := lastSet + 1
				if startSec <= endSection {
					//should first delay timeout
					timeout = time.After(ttl)
					getHeaders(startSec)
				} else {
					//done
					select {
					case d.acHeaderProcCh <- nil:
						return nil
					case <-d.cancelCh:
						return errCanceled
					}
				}
			case <-d.cancelCh:
				return errCanceled
			}

		case <-timeout:
			p.log.Debug("AcHeaders request time out", "elapse", ttl)
			return errTimeout
		}
	}
}

// processAcHeaders processes the AcHeaders, and fire the next synchronise flow.
func (d *Downloader) processAcHeaders(origin uint64) error {
	var lastHeader *types.Header
	for {
		select {
		case <-d.cancelCh:
			return errCanceled
		case headers := <-d.acHeaderProcCh:
			if len(headers) == 0 {
				// fetch the bloombits trie
				if lastHeader != nil {
					logging.Trace("all ac headers are processed, try fetch the latest blt")
					err := d.fetchBlt(lastHeader)
					if err != nil {
						return err
					}
				}
				//Told the header fetcher that the acHeaders are all handled
				d.verifiedAcHeaderCh <- nil
				return nil
			}
			lastHeader = headers[len(headers)-1]
			for i, acHeader := range headers {
				err := d.lightchain.VerifyAcHeader(acHeader, headers[:i])
				if err != nil {
					return err
				}
				// acHeader is legal, then:
				// 1. fetch the cht;
				// 2. fetch current acHeader's validator tries;
				// 3. (asynchronously)fetch all missing blocks before acHeader,
				// and do a simple verification using the cht, with no errors then just insert they into the chain.
				// 4. Then continue verifying the next acHeader.

				// 1.
				err = d.fetchCht(acHeader)
				if err != nil {
					logging.Debug("fetch cht failed", "headNum", acHeader.Number.Uint64(), "chtRoot", hexutil.Encode(acHeader.ChtRoot), "err", err)
					return err
				}
				// 2.
				err = d.FetchVldTrie(acHeader.ValRoot)
				if err != nil {
					logging.Debug("sync validator trie failed", "number", acHeader.Number, "valRoot", acHeader.ValRoot)
					return err
				}
				// 3.
				// send to verifiedAcHeaderCh for process.
				// the verifiedAcHeaderCh is a buffer channel, so it can be concurrently handling the next acHeader
				// while downloading headers (and bodies, receipts) before the currently verified acHeader.
				select {
				case <-d.cancelCh:
					return errCanceled
				case d.verifiedAcHeaderCh <- acHeader:
				}
			}
		}
	}
}

func (d *Downloader) fetchCht(header *types.Header) error {
	logging.Trace("start fetching cht", "headNum", header.Number.Uint64(), "chtRoot", hexutil.Encode(header.ChtRoot))
	return d.fetchAcTrie(d.syncCht, d.lightchain.UpdateTrustedCht, header.ChtRoot, header)
}

func (d *Downloader) fetchBlt(header *types.Header) error {
	logging.Trace("start fetching blt", "headNum", header.Number.Uint64(), "bltRoot", hexutil.Encode(header.BltRoot))
	return d.fetchAcTrie(d.syncBlt, d.lightchain.UpdateTrustedBlt, header.BltRoot, header)
}

func (d *Downloader) fetchAcTrie(fsync func(common.Hash) *trieSync, afterSync func(*types.Header) error, rootBytes []byte, header *types.Header) error {
	root := common.BytesToHash(rootBytes)
	tSync := fsync(root)
	//wait
	select {
	case <-tSync.done:
		// In this place, a ChtRoot or BltRoot will be a trusted one,
		// so if the sync success, we need to update the local records.
		if tSync.err == nil {
			return afterSync(header)
		}
		return tSync.err
	case <-d.quitCh:
		logging.Debug("cancel trie sync due to quit")
		tSync.Cancel()
		return errCanceled
	}
}

// fetchHeaders tries to fetch headers continuously until there's no more headers available.
// Note: the latest header maybe higher than the "height"
func (d *Downloader) fetchHeaders(p *peerConnection, from, height, firstNoneAc uint64) error {
	defer func() {
		logging.Trace("fetchHeaders quit")
	}()
	skeleton := height-firstNoneAc > 2*MaxSkeletonSize // Skeleton assembly phase or finishing up
	request := time.Now()                              // time of the last fetch request
	timeout := time.NewTimer(0)                        // timer to dump a non-responsive active peer
	<-timeout.C                                        // timeout channel should be initially empty
	defer timeout.Stop()

	var ttl time.Duration
	// A light-node don't need the `Validator` data on the header
	// for those blocks before a verified acHeader. So called a `light header`.
	lightHeader := d.mode == LightSync
	getHeaders := func(from uint64) {
		request = time.Now()

		ttl = d.requestTTL()
		timeout.Reset(ttl)

		if skeleton {
			p.log.Trace("Fetching skeleton headers", "count", MaxSkeletonSize, "from", from)
			go p.peer.RequestHeadersByNumber(from+uint64(MaxHeaderFetch)-1, int(MaxSkeletonSize), MaxHeaderFetch-1, false, false)
		} else {
			p.log.Trace("Fetching full headers", "count", MaxHeaderFetch, "from", from)
			go p.peer.RequestHeadersByNumber(from, MaxHeaderFetch, 0, false, false)
		}
	}
	for {
		select {
		case <-d.cancelCh:
			return errCanceled
		case acHeader := <-d.verifiedAcHeaderCh:
			if acHeader == nil {
				// all ac headers are handled, start fetching the none ac headers.
				logging.Trace("all ac headers are handled ( or there's no ac header to fetch)")
				from = firstNoneAc
				getHeaders(from)
				break // break select case
			}
			// We can directly download all blocks before the current acHeader,
			// and these blocks only needs some sanity checks.
			// Due to the acHeaders has a large span between each each others,
			// for a memory reason, we need to process section by section,
			// and we can take block hashes from the cht to form skeleton.
			atomic.StoreUint64(&d.latestValidAcNum, acHeader.Number.Uint64())

			shs, err := d.getAcSkeleton(from, acHeader)
			if err != nil {
				return fmt.Errorf("get skeleton from %d to %d error: %v", from, acHeader.Number.Uint64(), err)
			}
			logging.Trace("start filling ac header skeleton", "from", from)
			filled, proced, err := d.fillHeaderSkeleton(from, shs, lightHeader)
			if err == nil {
				rest := filled[proced:]
				logging.Trace("fill ac header skeleton finished", "from", from, "proced", proced, "rest", len(rest))
				if len(rest) > 0 {
					select {
					case d.headerProcCh <- rest:
					case <-d.cancelCh:
						return errCanceled
					}
				}
			} else {
				p.log.Debug("Skeleton chain invalid", "err", err)
				return errInvalidChain
			}
			// update "from" for the next section
			from = acHeader.Number.Uint64() + 1

		case packet := <-d.headerCh:
			// Make sure the active peer is giving us the skeleton headers
			if packet.PeerId() != p.id {
				logging.Debug("Received skeleton from incorrect peer", "peer", packet.PeerId())
				break
			}
			headerReqTimer.UpdateSince(request)
			timeout.Stop()
			// If the skeleton's finished, pull any remaining head headers directly from the origin
			if packet.Items() == 0 && skeleton {
				skeleton = false
				getHeaders(from)
				continue
			}

			// If no more headers are inbound, notify the content fetchers and return
			if packet.Items() == 0 {
				// no more headers, terminate the process
				p.log.Trace("No more headers available")
				select {
				case d.headerProcCh <- nil:
					return nil
				case <-d.cancelCh:
					return errCanceled
				}
			}

			headers := packet.(*headerPack).headers

			// If we received a skeleton batch, resolve internals concurrently
			if skeleton {
				shs := make([]*SkeletonHeader, len(headers))
				for i, h := range headers {
					shs[i] = &SkeletonHeader{h.Number.Uint64(), h.Hash()}
				}
				filled, proced, err := d.fillHeaderSkeleton(from, shs, false)
				if err != nil {
					p.log.Debug("Skeleton chain invalid", "err", err)
					return errInvalidChain
				}
				headers = filled[proced:]
				from += uint64(proced)
			}

			// Insert all the new headers and fetch the next batch
			if len(headers) > 0 {
				p.log.Trace("Scheduling new headers", "count", len(headers), "from", from)
				select {
				case d.headerProcCh <- headers:
				case <-d.cancelCh:
					return errCanceled
				}
				from += uint64(len(headers))
				getHeaders(from)
			} else {
				// No headers delivered, sleep a bit and retry
				p.log.Trace("All headers delivered, sleep a bit and retry")
				select {
				case <-time.After(fsHeaderContCheck):
					getHeaders(from)
					continue
				case <-d.cancelCh:
					return errCanceled
				}
			}

		case <-timeout.C:
			// Header retrieval timed out, consider the peer bad and drop
			p.log.Debug("Header request timed out", "elapsed", ttl)
			headerTimeoutMeter.Mark(1)
			d.dropPeer(p.id)

			// Finish the sync gracefully instead of dumping the gathered data though
			for _, ch := range []chan bool{d.bodyWakeCh, d.receiptWakeCh} {
				select {
				case ch <- false:
				case <-d.cancelCh:
				}
			}
			select {
			case d.headerProcCh <- nil:
			case <-d.cancelCh:
			}
			return errBadPeer
		}
	}
}

// getAcSkeleton returns the skeleton slice between startNum and acHeaderNum.
// Note: The last one is guaranteed to be the acHeader's info.
func (d *Downloader) getAcSkeleton(startNum uint64, acHeader *types.Header) ([]*SkeletonHeader, error) {
	acnum := acHeader.Number.Uint64()
	if startNum > acnum {
		return nil, fmt.Errorf("invalid startNum: %d and acHeader num: %d", startNum, acnum)
	}
	shs := make([]*SkeletonHeader, 0, ((acnum-startNum)/MaxSkeletonSize)+1)
	if acnum-startNum <= MaxSkeletonSize {
		sh := &SkeletonHeader{Number: acnum, Hash: acHeader.Hash()}
		shs = append(shs, sh)
	} else {
		for num := startNum + MaxSkeletonSize - 1; num < acnum; num += MaxSkeletonSize {
			hash, err := d.lightchain.GetHashFromCht(num)
			if err != nil {
				return nil, err
			}
			sh := &SkeletonHeader{Number: num, Hash: hash}
			shs = append(shs, sh)
		}
		//append current ac header hash
		sh := &SkeletonHeader{Number: acnum, Hash: acHeader.Hash()}
		shs = append(shs, sh)
	}
	return shs, nil
}

// fillHeaderSkeleton concurrently retrieves headers from all our available peers
// and maps them to the provided skeleton header chain.
//
// Any partial results from the beginning of the skeleton is (if possible) forwarded
// immediately to the header processor to keep the rest of the pipeline full even
// in the case of header stalls.
//
// The method returns the entire filled skeleton and also the number of headers
// already forwarded for processing.
func (d *Downloader) fillHeaderSkeleton(from uint64, skeleton []*SkeletonHeader, light bool) ([]*types.Header, int, error) {
	logging.Debug("Filling up skeleton", "from", from, "lenSkeleton", len(skeleton))
	d.queue.ScheduleSkeleton(from, skeleton)

	var (
		deliver = func(packet dataPack) (int, error) {
			pack := packet.(*headerPack)
			return d.queue.DeliverHeaders(pack.peerID, pack.headers, d.headerProcCh)
		}
		expire   = func() map[string]int { return d.queue.ExpireHeaders(d.requestTTL()) }
		throttle = func() bool { return false }
		reserve  = func(p *peerConnection, count int) (*fetchRequest, bool, error) {
			return d.queue.ReserveHeaders(p, count), false, nil
		}
		fetch    = func(p *peerConnection, req *fetchRequest) error { return p.FetchHeaders(req.From, req.Count, light) }
		capacity = func(p *peerConnection) int { return -1 } //for reserve func, not used.
		setIdle  = func(p *peerConnection, accepted int) { p.SetHeadersIdle(accepted) }
	)
	err := d.fetchParts(d.headerCh, deliver, d.queue.headerContCh, expire,
		d.queue.PendingHeaders, d.queue.InFlightHeaders, throttle, reserve,
		nil, fetch, d.queue.CancelHeaders, capacity, d.peers.HeaderIdlePeers, setIdle, "headers")

	logging.Debug("Skeleton fill terminated", "err", err)

	filled, proced := d.queue.RetrieveHeaders()
	return filled, proced, err
}

// fetchBodies iteratively downloads the scheduled block bodies, taking any
// available peers, reserving a chunk of blocks for each, waiting for delivery
// and also periodically checking for timeouts.
func (d *Downloader) fetchBodies() error {
	logging.Debug("Downloading block bodies")

	var (
		deliver = func(packet dataPack) (int, error) {
			pack := packet.(*bodyPack)
			return d.queue.DeliverBodies(pack.peerID, pack.transactions)
		}
		expire   = func() map[string]int { return d.queue.ExpireBodies(d.requestTTL()) }
		fetch    = func(p *peerConnection, req *fetchRequest) error { return p.FetchBodies(req) }
		capacity = func(p *peerConnection) int { return p.BlockCapacity(d.requestRTT()) }
		setIdle  = func(p *peerConnection, accepted int) { p.SetBodiesIdle(accepted) }
	)
	err := d.fetchParts(d.bodyCh, deliver, d.bodyWakeCh, expire,
		d.queue.PendingBlocks, d.queue.InFlightBlocks, d.queue.ShouldThrottleBlocks, d.queue.ReserveBodies,
		nil, fetch, d.queue.CancelBodies, capacity, d.peers.BodyIdlePeers, setIdle, "bodies")

	logging.Debug("Block body download terminated", "err", err)
	return err
}

// fetchReceipts iteratively downloads the scheduled block receipts, taking any
// available peers, reserving a chunk of receipts for each, waiting for delivery
// and also periodically checking for timeouts.
func (d *Downloader) fetchReceipts() error {
	logging.Debug("Downloading transaction receipts")

	var (
		deliver = func(packet dataPack) (int, error) {
			pack := packet.(*receiptPack)
			return d.queue.DeliverReceipts(pack.peerID, pack.receipts)
		}
		expire   = func() map[string]int { return d.queue.ExpireReceipts(d.requestTTL()) }
		fetch    = func(p *peerConnection, req *fetchRequest) error { return p.FetchReceipts(req) }
		capacity = func(p *peerConnection) int { return p.ReceiptCapacity(d.requestRTT()) }
		setIdle  = func(p *peerConnection, accepted int) { p.SetReceiptsIdle(accepted) }
	)
	err := d.fetchParts(d.receiptCh, deliver, d.receiptWakeCh, expire,
		d.queue.PendingReceipts, d.queue.InFlightReceipts, d.queue.ShouldThrottleReceipts, d.queue.ReserveReceipts,
		nil, fetch, d.queue.CancelReceipts, capacity, d.peers.ReceiptIdlePeers, setIdle, "receipts")

	logging.Debug("Transaction receipt download terminated", "err", err)
	return err
}

// fetchParts iteratively downloads scheduled block parts, taking any available
// peers, reserving a chunk of fetch requests for each, waiting for delivery and
// also periodically checking for timeouts.
//
// As the scheduling/timeout logic mostly is the same for all downloaded data
// types, this method is used by each for data gathering and is instrumented with
// various callbacks to handle the slight differences between processing them.
//
// The instrumentation parameters:
//  - errCancel:   error type to return if the fetch operation is cancelled (mostly makes logging nicer)
//  - deliveryCh:  channel from which to retrieve downloaded data packets (merged from all concurrent peers)
//  - deliver:     processing callback to deliver data packets into type specific download queues (usually within `queue`)
//  - wakeCh:      notification channel for waking the fetcher when new tasks are available (or sync completed)
//  - expire:      task callback method to abort requests that took too long and return the faulty peers (traffic shaping)
//  - pending:     task callback for the number of requests still needing download (detect completion/non-completability)
//  - inFlight:    task callback for the number of in-progress requests (wait for all active downloads to finish)
//  - throttle:    task callback to check if the processing queue is full and activate throttling (bound memory use)
//  - reserve:     task callback to reserve new download tasks to a particular peer (also signals partial completions)
//  - fetchHook:   tester callback to notify of new tasks being initiated (allows testing the scheduling logic)
//  - fetch:       network callback to actually send a particular download request to a physical remote peer
//  - cancel:      task callback to abort an in-flight download request and allow rescheduling it (in case of lost peer)
//  - capacity:    network callback to retrieve the estimated type-specific bandwidth capacity of a peer (traffic shaping)
//  - idle:        network callback to retrieve the currently (type specific) idle peers that can be assigned tasks
//  - setIdle:     network callback to set a peer back to idle and update its estimated capacity (traffic shaping)
//  - kind:        textual label of the type being downloaded to display in log mesages
func (d *Downloader) fetchParts(deliveryCh chan dataPack, deliver func(dataPack) (int, error), wakeCh chan bool,
	expire func() map[string]int, pending func() int, inFlight func() bool, throttle func() bool, reserve func(*peerConnection, int) (*fetchRequest, bool, error),
	fetchHook func([]*types.Header), fetch func(*peerConnection, *fetchRequest) error, cancel func(*fetchRequest), capacity func(*peerConnection) int,
	idle func() ([]*peerConnection, int), setIdle func(*peerConnection, int), kind string) error {

	// Create a ticker to detect expired retrieval tasks
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	update := make(chan struct{}, 1)

	// Prepare the queue and fetch block parts until the block header fetcher's done
	finished := false
	for {
		select {
		case <-d.cancelCh:
			return errCanceled

		case packet := <-deliveryCh:
			// If the peer was previously banned and failed to deliver its pack
			// in a reasonable time frame, ignore its message.
			if peer := d.peers.Peer(packet.PeerId()); peer != nil {
				// Deliver the received chunk of data and check chain validity
				accepted, err := deliver(packet)
				if err == errInvalidChain {
					return err
				}
				// Unless a peer delivered something completely else than requested (usually
				// caused by a timed out request which came through in the end), set it to
				// idle. If the delivery's stale, the peer should have already been idled.
				if err != errStaleDelivery {
					setIdle(peer, accepted)
				}
				// Issue a log to the user to see what's going on
				switch {
				case err == nil && packet.Items() == 0:
					peer.log.Trace("Requested data not delivered", "type", kind)
				case err == nil:
					peer.log.Trace("Delivered new batch of data", "type", kind, "count", packet.Stats())
				default:
					peer.log.Trace("Failed to deliver retrieved data", "type", kind, "err", err)
				}
			}
			// Blocks assembled, try to update the progress
			select {
			case update <- struct{}{}:
			default:
			}

		case cont := <-wakeCh:
			// The header fetcher sent a continuation flag, check if it's done
			if !cont {
				finished = true
			}
			// Headers arrive, try to update the progress
			select {
			case update <- struct{}{}:
			default:
			}

		case <-ticker.C:
			// Sanity check update the progress
			select {
			case update <- struct{}{}:
			default:
			}

		case <-update:
			// Short circuit if we lost all our peers
			if d.peers.Len() == 0 {
				return errNoPeers
			}
			// Check for fetch request timeouts and demote the responsible peers
			for pid, fails := range expire() {
				if peer := d.peers.Peer(pid); peer != nil {
					// If a lot of retrieval elements expired, we might have overestimated the remote peer or perhaps
					// ourselves. Only reset to minimal throughput but don't drop just yet. If even the minimal times
					// out that sync wise we need to get rid of the peer.
					//
					// The reason the minimum threshold is 2 is because the downloader tries to estimate the bandwidth
					// and latency of a peer separately, which requires pushing the measures capacity a bit and seeing
					// how response times reacts, to it always requests one more than the minimum (i.e. min 2).
					if fails > 2 {
						peer.log.Trace("Data delivery timed out", "type", kind)
						setIdle(peer, 0)
					} else {
						peer.log.Debug("Stalling delivery, dropping", "type", kind)
						d.dropPeer(pid)

						// If this peer was the master peer, abort sync immediately
						d.cancelLock.RLock()
						master := pid == d.cancelPeer
						d.cancelLock.RUnlock()

						if master {
							d.cancel()
							return errTimeout
						}
					}
				}
			}
			// If there's nothing more to fetch, wait or terminate
			if pending() == 0 {
				if !inFlight() && finished {
					logging.Debug("Data fetching completed", "type", kind)
					return nil
				}
				break
			}
			// Send a download request to all idle peers, until throttled
			progressed, throttled, running := false, false, inFlight()
			idles, total := idle()

			for _, peer := range idles {
				// Short circuit if throttling activated
				if throttle() {
					throttled = true
					break
				}
				// Short circuit if there is no more available task.
				if pending() == 0 {
					break
				}
				// Reserve a chunk of fetches for a peer. A nil can mean either that
				// no more headers are available, or that the peer is known not to
				// have them.
				request, progress, err := reserve(peer, capacity(peer))
				if err != nil {
					return err
				}
				if progress {
					progressed = true
				}
				if request == nil {
					continue
				}
				if request.From > 0 {
					peer.log.Trace("Requesting new batch of data", "type", kind, "from", request.From)
				} else {
					peer.log.Trace("Requesting new batch of data", "type", kind, "count", len(request.Headers), "from", request.Headers[0].Number)
				}
				// Fetch the chunk and make sure any errors return the hashes to the queue
				if fetchHook != nil {
					fetchHook(request.Headers)
				}
				if err := fetch(peer, request); err != nil {
					// Although we could try and make an attempt to fix this, this error really
					// means that we've double allocated a fetch task to a peer. If that is the
					// case, the internal state of the downloader and the queue is very wrong so
					// better hard crash and note the error instead of silently accumulating into
					// a much bigger issue.
					panic(fmt.Sprintf("%v: %s fetch assignment failed", peer, kind))
				}
				running = true
			}
			// Make sure that we have peers available for fetching. If all peers have been tried
			// and all failed throw an error
			if !progressed && !throttled && !running && len(idles) == total && pending() > 0 {
				return errPeersUnavailable
			}
		}
	}
}

// processHeaders takes batches of retrieved headers from an input channel and
// keeps processing and scheduling them into the header chain and downloader's
// queue until the stream ends or a failure occurs.
//
// There are two main logic on this function: 1. try insert header chain; 2. scheduling the headers to download bodies and receipts.
// For FullSync, we do only step 2; for LightSync, we do only step 1; for FastSync, we do both 1 and 2.
func (d *Downloader) processHeaders(origin uint64) error {
	defer func() {
		logging.Trace("processHeaders quit")
	}()
	// Wait for batches of headers to process
	gotHeaders := false
	var tails []*types.Header // Cache the tail blocks for a leapfrog synchronising
	for {
		select {
		case <-d.cancelCh:
			return errCanceled

		case headers := <-d.headerProcCh:
			// Terminate header processing if we synced up
			if len(headers) == 0 {
				if len(tails) > 0 {
					//It sure is fast or light sync
					if n, err := d.lightchain.InsertHeaderChain(tails); err != nil {
						logging.Debug("Invalid header encountered", "number", tails[n].Number, "hash", tails[n].Hash(), "err", err)
						return errInvalidChain
					}
					if d.mode == FastSync {
						inserts := d.queue.Schedule(tails, origin)
						if len(inserts) != len(tails) {
							logging.Debug("Stale headers")
							return errBadPeer
						}
						// ordinarily there exist handling of the origin, such as origin += len(tails),
						// but this's not need here, cause the origin variable won't be used any more.
					} else if d.mode == LightSync {
						select {
						case d.insertedHeaderCh <- tails:
						case <-d.cancelCh:
							return errCanceled
						}
					}
				}
				logging.Trace("processHeaders notify everyone that headers are fully processed")
				if d.mode != LightSync {
					// Notify everyone that headers are fully processed
					for _, ch := range []chan bool{d.bodyWakeCh, d.receiptWakeCh} {
						select {
						case ch <- false:
						case <-d.cancelCh:
						}
					}
				} else {
					select {
					case d.insertedHeaderCh <- nil:
					case <-d.cancelCh:
					}
				}
				if !gotHeaders {
					return errStallingPeer
				}
				return nil
			} else {
				logging.Trace("processHeaders receive headers", "from", headers[0].Number, "count", len(headers))
				if len(tails) > 0 {
					logging.Debug("processHeaders last tail", "from", tails[0].Number, "count", len(tails))
					lenOld, lenNew := len(tails), len(headers)
					s := make([]*types.Header, lenOld+lenNew)
					copy(s[:lenOld], tails)
					copy(s[lenOld:], headers)
					headers = s
					tails = nil
				}
			}
			// Otherwise split the chunk of headers into batches and process them
			gotHeaders = true
			latestValidAcNum := atomic.LoadUint64(&d.latestValidAcNum)
			// Headers are coming in batch from fillHeaderSkeleton or from fetchHeaders,
			// so headers in the same batch are ether all guaranteed by the latest acHeader or not.
			guaranteed := headers[len(headers)-1].Number.Uint64() <= latestValidAcNum

			for len(headers) > 0 {
				// Terminate if something failed in between processing chunks
				select {
				case <-d.cancelCh:
					return errCanceled
				default:
				}
				// Select the next chunk of headers to import
				limit := maxHeadersProcess
				if limit > len(headers) {
					limit = len(headers)
				}
				// Before done, make sure that the last header number in every chunk is a multiple of leapfrogStep
				if !guaranteed && (d.mode == FastSync || d.mode == LightSync) {
					num := headers[limit-1].Number.Uint64()
					lastIndex := limit - int(num%d.leapfrogStep)
					if lastIndex <= 0 {
						tails = headers
						headers = nil
						break //break for loop
					} else {
						limit = lastIndex
					}
				}
				chunk := headers[:limit]
				// In case of header only syncing, validate the chunk immediately
				if d.mode == FastSync || d.mode == LightSync {
					logging.Trace("processHeaders handle chunk", "from", chunk[0].Number, "count", len(chunk), "guaranteed", guaranteed)
					if guaranteed {
						if n, err := d.lightchain.InsertGuaranteedHeaderChain(chunk); err != nil {
							logging.Error("SHOULD NOT HAPPENED! Invalid header encountered", "number", chunk[n].Number, "hash", chunk[n].Hash(), "err", err)
							return errInvalidChain
						}
					} else {
						//
						if n, err := d.lightchain.InsertHeaderChain(chunk); err != nil {
							logging.Info("Invalid header encountered", "number", chunk[n].Number, "hash", chunk[n].Hash(), "err", err)
							return errInvalidChain
						}
					}

					if d.mode == LightSync {
						select {
						case d.insertedHeaderCh <- chunk:
						case <-d.cancelCh:
							return errCanceled
						}
					}
				}
				// Unless we're doing light chains, schedule the headers for associated content retrieval
				if d.mode != LightSync {
					// If we've reached the allowed number of pending headers, stall a bit
					for d.queue.PendingBlocks() >= maxQueuedHeaders || d.queue.PendingReceipts() >= maxQueuedHeaders {
						select {
						case <-d.cancelCh:
							return errCanceled
						case <-time.After(time.Second):
						}
					}
					// Otherwise insert the headers for content retrieval
					inserts := d.queue.Schedule(chunk, origin)
					if len(inserts) != len(chunk) {
						logging.Debug("Stale headers")
						return errBadPeer
					}
				}
				headers = headers[limit:]
				origin += uint64(limit)
			}
			// Update the highest block number we know if a higher one is found.
			d.syncStatsLock.Lock()
			if d.syncStatsChainHeight < origin {
				d.syncStatsChainHeight = origin - 1
			}
			d.syncStatsLock.Unlock()

			if d.mode != LightSync {
				// Signal the content downloaders of the availablility of new tasks
				for _, ch := range []chan bool{d.bodyWakeCh, d.receiptWakeCh} {
					select {
					case ch <- true:
					default:
					}
				}
			}
		}
	}
}

func (d *Downloader) prepareForFullSync(origin uint64) error {
	defer func() {
		logging.Trace("prepareForFullSync quit")
	}()
	// check if the previous fast-sync is completely success,
	// if not, try to do some remediation.
	flag := rawdb.ReadFastSyncUndoneFlag(d.chainDb)
	if flag == FastUndone {
		// previous fast-sync is not fully done
		// check fastVld
		parentNum := origin - 1
		fastVld := rawdb.ReadFastVldTrieHeight(d.chainDb)
		oldestNeed := origin - d.stakeLookBack
		if oldestNeed > origin {
			oldestNeed = 1
		}
		start := oldestNeed
		if start < fastVld {
			start = fastVld
		}

		if start <= parentNum {
			logging.Info("prepareForFullSync: try fetch missing validator trie", "fastVld", fastVld, "oldestNeed", oldestNeed, "latest", parentNum)
			for i := start; i <= parentNum; i++ {
				header := d.lightchain.GetHeaderByNumber(i)
				err := d.FetchVldTrie(header.ValRoot)
				if err != nil {
					return fmt.Errorf("try fetch missing validator trie failed. err=%v", err)
				}
			}
		}
		// need only to sync the latest state and stakingTrie
		logging.Info("prepareForFullSync: try fetch missing state", "number", parentNum)
		parent := d.lightchain.GetHeaderByNumber(parentNum)
		stateSync := d.syncState(parent.Root)
		err := stateSync.Wait()
		if err != nil {
			return fmt.Errorf("try fetch missing state failed. err=%v", err)
		}
		err = d.fetchStakingTrie(parent.StakingRoot)
		if err != nil {
			return fmt.Errorf("try fetch missing staking trie failed. err=%v", err)
		}
		// remediation done, set the fast-sync undone flag
		rawdb.WriteFastSyncUndoneFlag(d.chainDb, FastLightDone)
		logging.Info("prepareForFullSync done")
	}
	// signal to start
	d.verifiedAcHeaderCh <- nil
	return nil
}

// processFullSyncContent takes fetch results from the queue and imports them into the chain.
func (d *Downloader) processFullSyncContent(origin uint64) error {
	defer func() {
		logging.Trace("processFullSyncContent quit")
	}()
	for {
		logging.Debug("processFullSyncContent wait results")
		results := d.queue.Results(true)
		if len(results) == 0 {
			logging.Debug("processFullSyncContent done")
			return nil
		}

		if err := d.importBlockResults(results); err != nil {
			return err
		}
	}
}

func (d *Downloader) importBlockResults(results []*fetchResult) error {
	// Check for any early termination requests
	if len(results) == 0 {
		return nil
	}
	select {
	case <-d.quitCh:
		return errCancelContentProcessing
	default:
	}
	// Retrieve the a batch of results to import
	first, last := results[0].Header, results[len(results)-1].Header
	logging.Trace("Inserting downloaded chain", "items", len(results),
		"firstnum", first.Number, "firsthash", first.Hash(),
		"lastnum", last.Number, "lasthash", last.Hash(),
	)
	blocks := make([]*types.Block, len(results))
	for i, result := range results {
		blocks[i] = types.NewBlockWithHeader(result.Header).WithBody(&types.Body{Transactions: result.Transactions})
	}
	if err := d.blockchain.InsertChain(blocks); err != nil {
		logging.Debug("Downloaded item processing failed", "err", err)
		return errInvalidChain
	}
	return nil
}

// processFastSyncContent takes fetch results from the queue and writes them to the
// database. It also controls the synchronisation of validator trie and state nodes of the latest blocks.
func (d *Downloader) processFastSyncContent(latest *types.Header) error {
	rawdb.WriteFastSyncUndoneFlag(d.chainDb, FastUndone)
	needVld := latest.Number.Uint64() - d.stakeLookBack - 1
	if needVld > latest.Number.Uint64() {
		//overflow
		needVld = 1
	}

	newLatest := latest
	for {
		// Wait for the next batch of downloaded data to be available
		results := d.queue.Results(true)
		if len(results) == 0 {
			logging.Debug("try sync the last staking trie", "num", newLatest.Number, "root", newLatest.StakingRoot.String())
			if err := d.fetchStakingTrie(newLatest.StakingRoot); err != nil {
				logging.Info("processFastSyncContent sync staking trie error", "err", err)
				return err
			}
			logging.Debug("try sync the last state", "num", newLatest.Number, "root", newLatest.Root.String())
			stateSync := d.syncState(newLatest.Root)
			// just wait. the syncing of trie can not be concurrent
			select {
			case <-stateSync.done:
				if stateSync.err != nil {
					logging.Info("processFastSyncContent state sync error", "err", stateSync.err)
					return stateSync.err
				}
				rawdb.WriteFastSyncUndoneFlag(d.chainDb, FastLightDone)
				logging.Trace("processFastSyncContent done")
				return nil
			case <-d.cancelCh:
				logging.Info("processFastSyncContent canceled", "cause", "d.cancelCh")
				return errCancelTrieFetch
			}
		}

		// fast commit
		logging.Debug("got fast sync results, try to commit", "count", len(results))
		li := len(results) - 1
		postEvent := results[li].Header.Number.Cmp(newLatest.Number) >= 0
		if err := d.commitFastSyncData(results, postEvent); err != nil {
			return err
		}
		if results[li].Header.Number.Cmp(newLatest.Number) > 0 {
			newLatest = results[li].Header
		}
		// check the blocks needed to sync validators trie
		if results[li].Header.Number.Uint64() >= needVld {
			for _, req := range results {
				if req.Header.Number.Uint64() >= needVld {
					logging.Debug("try sync latest validators", "headNum", req.Header.Number, "valRoot", req.Header.ValRoot.String())
					vldSync := d.syncVldTrie(req.Header.ValRoot)
					// just wait. the syncing of trie can not be concurrent
					select {
					case <-vldSync.done:
						if vldSync.err != nil {
							logging.Info("processFastSyncContent validators sync error", "err", vldSync.err)
							return vldSync.err
						}
						// update the fast vld height
						rawdb.WriteFastVldTrieHeight(d.chainDb, req.Header.Number.Uint64())
					case <-d.cancelCh:
						logging.Info("processFastSyncContent canceled", "cause", "d.cancelCh")
						return errCanceled
					}
				}
			}
		}
	}
}

func (d *Downloader) commitFastSyncData(results []*fetchResult, postEvent bool) error {
	// Check for any early termination requests
	if len(results) == 0 {
		return nil
	}
	// Retrieve the a batch of results to import
	first, last := results[0].Header, results[len(results)-1].Header
	logging.Trace("Inserting fast-sync blocks", "items", len(results),
		"firstnum", first.Number, "firsthash", first.Hash(),
		"lastnumn", last.Number, "lasthash", last.Hash(),
	)
	blocks := make([]*types.Block, len(results))
	receipts := make([]types.Receipts, len(results))
	for i, result := range results {
		blocks[i] = types.NewBlockWithHeader(result.Header).WithBody(&types.Body{Transactions: result.Transactions})
		receipts[i] = result.Receipts
	}
	if index, err := d.blockchain.InsertReceiptChain(blocks, receipts, postEvent); err != nil {
		logging.Debug("Downloaded item processing failed", "number", results[index].Header.Number, "hash", results[index].Header.Hash(), "err", err)
		return errInvalidChain
	}
	return nil
}

// processLightSync synchronise some latest validator trie and state trie.
func (d *Downloader) processLightSync(latest *types.Header) error {
	rawdb.WriteFastSyncUndoneFlag(d.chainDb, LightUndone)
	needVld := latest.Number.Uint64() - d.stakeLookBack - 1
	if needVld > latest.Number.Uint64() {
		//overflow
		needVld = 1
	}

	newLatest := latest
	for {
		select {
		case <-d.cancelCh:
			return errCanceled
		case headers := <-d.insertedHeaderCh:
			if len(headers) == 0 {
				return d.handleLastBlockForLightSync(newLatest, false, false)
			}

			// cache the latest headers
			logging.Debug("got light sync inserted headers", "count", len(headers))
			li := len(headers) - 1
			if headers[li].Number.Cmp(newLatest.Number) > 0 {
				newLatest = headers[li]
			}
			// fetch some mid-term blocks
			idx := int(params.ACoCHTFrequency - headers[0].Number.Uint64()%params.ACoCHTFrequency)
			for ln := len(headers); idx < ln; idx += int(params.ACoCHTFrequency) {
				header := headers[idx]
				err := d.handleLastBlockForLightSync(header, true, header.Number.Uint64() < needVld)
				if err != nil {
					return err
				}
			}
			// check the blocks needed to sync validators trie
			if headers[li].Number.Uint64() >= needVld {
				for _, header := range headers {
					if header.Number.Uint64() >= needVld {
						logging.Debug("try sync latest validators", "headNum", header.Number, "valRoot", header.ValRoot.String())
						vldSync := d.syncVldTrie(header.ValRoot)
						// just wait. the syncing of trie can not be concurrent
						select {
						case <-vldSync.done:
							if vldSync.err != nil {
								logging.Info("processLightSync validators sync error", "err", vldSync.err)
								return vldSync.err
							}
							// update the fast vld height
							rawdb.WriteFastVldTrieHeight(d.chainDb, header.Number.Uint64())
						case <-d.cancelCh:
							logging.Info("processLightSync canceled", "cause", "d.cancelCh")
							return errCanceled
						}
					}
				}
			}
		}
	}
}

func (d *Downloader) handleLastBlockForLightSync(last *types.Header, isNotFinish bool, needVld bool) error {
	// fetch the latest block
	num := last.Number.Uint64()
	logging.Debug("try to start the fetch of the block", "num", num)
	// We must first reset the queue.resultOffset by calling queue.Prepare
	d.queue.Prepare(num, d.mode)
	// Then we can schedule headers not before num for fetching bodies and receipts.
	// Actually we need only one block here.
	inserts := d.queue.Schedule([]*types.Header{last}, num)
	if len(inserts) != 1 {
		logging.Debug("Stale headers")
		return errBadPeer
	}
	// wake up body and receipt fetchers
	for _, ch := range []chan bool{d.bodyWakeCh, d.receiptWakeCh} {
		select {
		case ch <- isNotFinish:
		case <-d.cancelCh:
			return errCanceled
		}
	}

	logging.Debug("try sync the staking trie", "num", last.Number, "root", last.StakingRoot.String())
	if err := d.fetchStakingTrie(last.StakingRoot); err != nil {
		logging.Info("processLightSync syncing staking trie error", "err", err)
		return err
	}
	logging.Debug("try sync the state", "num", last.Number, "root", last.Root)
	stateSync := d.syncState(last.Root)
	// just wait. the syncing of trie can not be concurrent
	select {
	case <-stateSync.done:
		if stateSync.err != nil {
			logging.Info("processLightSync state sync error", "err", stateSync.err)
			return stateSync.err
		}
	case <-d.cancelCh:
		logging.Info("processLightSync canceled", "cause", "d.cancelCh")
		return errCancelTrieFetch
	}

	if needVld {
		if err := d.FetchVldTrie(last.ValRoot); err != nil {
			logging.Warn("processLightSync fetch vldtrie failed", "err", err)
			return err
		}
	}
	// wait and get the results
	results := d.queue.Results(true)
	if len(results) == 0 {
		return errors.New("fetch the latest block failed")
	}
	logging.Debug("got light sync block results, try to commit", "count", len(results))
	if err := d.commitFastSyncData(results, true); err != nil {
		return err
	}
	if !isNotFinish {
		rawdb.WriteFastSyncUndoneFlag(d.chainDb, FastLightDone)
		logging.Trace("processLightSync done")
	}
	return nil
}

// findAncestor tries to locate the common ancestor link of the local chain and
// a remote peers blockchain. In the general case when our node was in sync and
// on the correct chain, checking the top N links should already get us a match.
// In the rare scenario when we ended up on a long reorganisation (i.e. none of
// the head links match), we do a binary search to find the common ancestor.
func (d *Downloader) findAncestor(p *peerConnection, remoteHeader *types.Header) (uint64, error) {
	var (
		floor        uint64
		localHeight  uint64
		remoteHeight = remoteHeader.Number.Uint64()
	)
	switch d.mode {
	case FullSync, FastSync:
		localHeight = d.blockchain.CurrentBlock().NumberU64()
	case LightSync:
		localHeight = d.lightchain.CurrentHeader().Number.Uint64()
	}
	if localHeight == 0 {
		// Brand new sync, just return so that take the genesis as common ancestor.
		// Because the genesis hash was checked when handshaking with that peer, so we don't need to check it again.
		return 0, nil
	}

	if localHeight > maxForkBlocksCount {
		floor = localHeight - maxForkBlocksCount
	}
	if d.mode == LightSync {
		// for a light client, floor must not go below the start header
		lightStart := d.lightchain.GetLightStartHeader()
		if lightStart != nil {
			if lightStart.Number.Uint64() > floor {
				floor = lightStart.Number.Uint64()
			}
		}
	}
	logging.Info("Looking for common ancestor.", "local", localHeight, "floor", floor, "remote", remoteHeight)

	// Because it will barely fork for BFT-like consensus, so we just search a little back first.
	count, span := 8, 2
	from, max := localHeight-uint64((count-1)*span), localHeight
	if from > localHeight {
		// over flow
		from = 1
	}
	logging.Info("calculateRequestSpan", "from", from, "count", count, "skip", span-1, "max", max)

	go p.peer.RequestHeadersByNumber(from, count, span-1, false, true)
	// Wait for the remote response to the head fetch
	number, hash := uint64(0), common.Hash{}

	ttl := d.requestTTL()
	timeout := time.After(ttl)

	for finished := false; !finished; {
		select {
		case <-d.cancelCh:
			return 0, errCancelHeaderFetch
		case packet := <-d.headerCh:
			if packet.PeerId() != p.id {
				logging.Debug("Received blocks from incorrect peer", "pid", packet.PeerId())
				break
			}
			headers := packet.(*headerPack).headers
			if len(headers) == 0 {
				logging.Warn("Empty head header set from peer", "pid", p.id)
				return 0, errEmptyHeaderSet
			}
			// Make sure the peer's reply conforms to the request
			for i, header := range headers {
				expectNumber := from + uint64(i*span)
				if number := header.Number.Uint64(); number != expectNumber {
					logging.Warn("Head headers broke chain ordering", "index", i, "requested", expectNumber, "received", number)
					return 0, errInvalidChain
				}
			}
			// Check if a common ancestor was found
			finished = true
			for i := len(headers) - 1; i >= 0; i-- {
				// Skip any headers that underflow/overflow our requested set
				if headers[i].Number.Uint64() < from || headers[i].Number.Uint64() > max {
					continue
				}
				// Otherwise check if we already know the header or not
				h := headers[i].Hash()
				n := headers[i].Number.Uint64()

				if header := d.lightchain.GetHeaderByNumber(n); header != nil && header.Hash() == h {
					number, hash = n, h
					break
				}
			}
		case <-d.bodyCh:
		case <-d.receiptCh:
		case <-timeout:
			logging.Debug("Waiting for block hash timed out", "elapsed", ttl)
			return 0, errTimeout
		}
	}

	// If the head fetch already found an ancestor, return
	if hash != (common.Hash{}) {
		if number < floor {
			logging.Warn("Ancestor below allowance", "number", number, "hash", hash.String(), "allowance", floor)
			return 0, errInvalidAncestor
		}
		return number, nil
	}

	// Ancestor not found, we need to binary search over our chain
	start, end := uint64(0), localHeight
	if floor > 0 {
		start = floor
	}
	logging.Trace("Binary searching for common ancestor", "start", start, "end", end)

	for start+1 < end {
		// Split our chain interval in two, and request the hash to cross check
		check := (start + end) / 2

		ttl := d.requestTTL()
		timeout := time.After(ttl)

		logging.Trace("Looking for common ancestor.", "local", check)
		//go p.peer.RequestBlockHashByNumber(big.NewInt(int64(check)))
		go p.peer.RequestHeadersByNumber(check, 1, 0, false, true)

		// Wait until a reply arrives to this request
		for arrived := false; !arrived; {
			select {
			case <-d.cancelCh:
				return 0, errCancelHeaderFetch

			case packet := <-d.headerCh:
				// Discard anything not from the origin peer
				if packet.PeerId() != p.id {
					logging.Debug("Received headers from incorrect peer", "peer", packet.PeerId())
					break
				}

				// Make sure the peer actually gave something valid
				headers := packet.(*headerPack).headers
				if len(headers) != 1 {
					logging.Debug("Multiple headers for single request", "headers", len(headers))
					return 0, errBadPeer
				}
				arrived = true

				// Modify the search interval based on the response
				h := headers[0].Hash()
				n := headers[0].Number.Uint64()

				if header := d.lightchain.GetHeaderByNumber(n); header == nil || header.Hash() != h {
					end = check
					break
				}
				header := d.lightchain.GetHeaderByHash(h) // Independent of sync mode, header surely exists
				if header.Number.Uint64() != check {
					logging.Debug("Received non requested header", "number", header.Number, "hash", header.Hash(), "request", check)
					return 0, errBadPeer
				}
				start = check
				hash = h

			case <-d.bodyCh:
			case <-d.receiptCh:
			case <-timeout:
				logging.Info("Waiting for search header timed out", "elapsed", ttl)
				return 0, errTimeout
			}
		}
	}

	// Ensure valid ancestry and return
	if start < floor {
		logging.Warn("Ancestor below allowance", "number", start, "hash", hash.String(), "allowance", floor)
		return 0, errInvalidAncestor
	}

	return start, nil
}

// cancel aborts all of the operations and resets the queue. However, cancel does
// not wait for the running download goroutines to finish. This method should be
// used when cancelling the downloads from inside the downloader.
func (d *Downloader) cancel() {
	// Close the current cancel channel
	d.cancelLock.Lock()
	if d.cancelCh != nil {
		select {
		case <-d.cancelCh:
			// Channel was already closed
		default:
			close(d.cancelCh)
		}
	}
	d.cancelLock.Unlock()
}

// Cancel aborts all of the operations and waits for all download goroutines to
// finish before returning.
func (d *Downloader) Cancel() {
	d.cancel()
	d.cancelWg.Wait()
}

// Terminate interrupts the downloader, canceling all pending operations.
// The downloader cannot be reused after calling Terminate.
func (d *Downloader) Terminate() {
	// Close the termination channel (make sure double close is allowed)
	d.quitLock.Lock()
	select {
	case <-d.quitCh:
	default:
		close(d.quitCh)
	}
	d.quitLock.Unlock()

	// Cancel any pending download requests
	d.Cancel()
}

// requestTTL returns the current timeout allowance for a single download request
// to finish under.
func (d *Downloader) requestTTL() time.Duration {
	var (
		rtt  = time.Duration(atomic.LoadUint64(&d.rttEstimate))
		conf = float64(atomic.LoadUint64(&d.rttConfidence)) / 1000000.0
	)
	ttl := time.Duration(ttlScaling) * time.Duration(float64(rtt)/conf)
	if ttl > ttlLimit {
		ttl = ttlLimit
	}
	return ttl
}

func (d *Downloader) fetchHeight(p *peerConnection) (*types.Header, error) {

	// Request the advertised remote head block and wait for the response
	head, number := p.peer.Head()
	go func() {
		if err := p.peer.RequestHeadersByHash(head, 1, 0, false, true); err != nil {
			logging.Error("RequestHeadersByHash", "err", err)
		}
	}()

	ttl := d.requestTTL()
	timeout := time.After(ttl)
	logging.Trace("fetchHeight", "timeout", ttl, "p", p.id, "head", head.String(), "number", number)
	for {
		select {
		case <-d.cancelCh:
			logging.Debug("fetchHeight cancel", "err", errCancelHeaderFetch)
			return nil, errCancelHeaderFetch

		case packet := <-d.headerCh:
			logging.Trace("fetchHeight: receive header packet", "peerId", packet.PeerId(), "items", packet.Items(), "stats", packet.Stats())
			// Discard anything not from the origin peer
			if packet.PeerId() != p.id {
				logging.Warn("fetchHeight: Received headers from incorrect peer", "peer", packet.PeerId())
				break
			}
			// Make sure the peer actually gave something valid
			headers := packet.(*headerPack).headers
			if len(headers) != 1 {
				logging.Debug("fetchHeight: Multiple headers for single request", "headers", len(headers))
				return nil, errBadPeer
			}
			head := headers[0]
			return head, nil

		case <-timeout:
			logging.Debug("fetchHeight: Waiting for head header timed out", "elapsed", ttl)
			return nil, errTimeout

		case <-d.bodyCh:
			logging.Debug("fetchHeight: Out of bounds delivery, ignore bodyCh")
		case <-d.receiptCh:
			logging.Debug("Out of bounds delivery, ignore receiptCh")
			// Out of bounds delivery, ignore
		}
	}
}

// DeliverHeaders injects a new batch of block headers received from a remote
// node into the download schedule.
func (d *Downloader) DeliverHeaders(id string, headers []*types.Header) (err error) {
	ch := d.headerCh
	if d.acfilter.Exist(id) {
		ch = d.acHeaderCh
	}
	return d.deliver(id, ch, &headerPack{id, headers}, "headers")
}

// DeliverBodies injects a new batch of block bodies received from a remote node.
func (d *Downloader) DeliverBodies(id string, transactions [][]*types.Transaction) (err error) {
	return d.deliver(id, d.bodyCh, &bodyPack{id, transactions}, "bodies")
}

// DeliverReceipts injects a new batch of receipts received from a remote node.
func (d *Downloader) DeliverReceipts(id string, receipts [][]*types.Receipt) (err error) {
	logging.Debug("receive receipts response", "count", len(receipts))
	return d.deliver(id, d.receiptCh, &receiptPack{id, receipts}, "receipts")
}

func (d *Downloader) DeliverNodeData(id string, data [][]byte) (err error) {
	return d.deliver(id, d.trieCh, &triePack{id, data}, "nodedata")
}

// deliver injects a new batch of data received from a remote node.
func (d *Downloader) deliver(id string, destCh chan dataPack, packet dataPack, topic string) (err error) {
	// Deliver or abort if the sync is canceled while queuing
	d.cancelLock.RLock()
	cancel := d.cancelCh
	d.cancelLock.RUnlock()
	if cancel == nil {
		logging.Warn("cancel is nil", "topic", topic)
		return errNoSyncActive
	}
	select {
	case destCh <- packet:
		return nil
	case <-cancel:
		logging.Warn("<-cancel", "topic", topic)
		return errNoSyncActive
	}
}

// RegisterPeer injects a new download peer into the set of block source to be
// used for fetching hashes and blocks from.
func (d *Downloader) RegisterPeer(id string, peer Peer) error {
	logger := logging.New("peer", id)
	if err := d.peers.Register(newPeerConnection(id, peer, logger)); err != nil {
		logging.Error("Failed to register sync peer", "peer", id, "err", err)
		return err
	}
	d.qosReduceConfidence()

	return nil
}

func (d *Downloader) UnregisterPeer(id string) error {
	// Unregister the peer from the active peer set and revoke any fetch tasks
	logging.Debug("Unregistering sync peer", "pid", id)
	if err := d.peers.Unregister(id); err != nil {
		logging.Error("Failed to unregister sync peer", "peer", id, "err", err)
		return err
	}

	// If this peer was the master peer, abort sync immediately
	d.cancelLock.RLock()
	master := id == d.cancelPeer
	d.cancelLock.RUnlock()

	if master {
		d.cancel()
	}
	return nil
}

// qosTuner is the quality of service tuning loop that occasionally gathers the
// peer latency statistics and updates the estimated request round trip time.
func (d *Downloader) qosTuner() {
	for {
		// Retrieve the current median RTT and integrate into the previoust target RTT
		rtt := time.Duration((1-qosTuningImpact)*float64(atomic.LoadUint64(&d.rttEstimate)) + qosTuningImpact*float64(d.peers.medianRTT()))
		atomic.StoreUint64(&d.rttEstimate, uint64(rtt))

		// A new RTT cycle passed, increase our confidence in the estimated RTT
		conf := atomic.LoadUint64(&d.rttConfidence)
		conf = conf + (1000000-conf)/2
		atomic.StoreUint64(&d.rttConfidence, conf)

		// Log the new QoS values and sleep until the next RTT
		logging.Debug("Recalculated downloader QoS values", "rtt", rtt, "confidence", float64(conf)/1000000.0, "ttl", d.requestTTL())
		select {
		case <-d.quitCh:
			return
		case <-time.After(rtt):
		}
	}
}

// qosReduceConfidence is meant to be called when a new peer joins the downloader's
// peer set, needing to reduce the confidence we have in out QoS estimates.
func (d *Downloader) qosReduceConfidence() {
	// If we have a single peer, confidence is always 1
	peers := uint64(d.peers.Len())
	if peers == 0 {
		// Ensure peer connectivity races don't catch us off guard
		return
	}
	if peers == 1 {
		atomic.StoreUint64(&d.rttConfidence, 1000000)
		return
	}
	// If we have a ton of peers, don't drop confidence)
	if peers >= uint64(qosConfidenceCap) {
		return
	}
	// Otherwise drop the confidence factor
	conf := atomic.LoadUint64(&d.rttConfidence) * (peers - 1) / peers
	if float64(conf)/1000000 < rttMinConfidence {
		conf = uint64(rttMinConfidence * 1000000)
	}
	atomic.StoreUint64(&d.rttConfidence, conf)

	rtt := time.Duration(atomic.LoadUint64(&d.rttEstimate))
	logging.Debug("Relaxed downloader QoS values", "rtt", rtt, "confidence", float64(conf)/1000000.0, "ttl", d.requestTTL())
}

// requestRTT returns the current target round trip time for a download request
// to complete in.
//
// Note, the returned RTT is .9 of the actually estimated RTT. The reason is that
// the downloader tries to adapt queries to the RTT, so multiple RTT values can
// be adapted to, but smaller ones are preferred (stabler download stream).
func (d *Downloader) requestRTT() time.Duration {
	return time.Duration(atomic.LoadUint64(&d.rttEstimate)) * 9 / 10
}
