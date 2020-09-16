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

package fetcher

import (
	"errors"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/logging"
	"math/rand"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"

	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
)

const (
	arriveTimeout = 500 * time.Millisecond // Time allowance before an announced block is explicitly requested
	gatherSlack   = 100 * time.Millisecond // Interval used to collate almost-expired announces with fetches
	fetchTimeout  = 5 * time.Second        // Maximum allotted time to return an explicitly requested block
	maxUncleDist  = 7                      // Maximum allowed backward distance from the chain head
	maxQueueDist  = 32                     // Maximum allowed distance from the chain head to queue
	hashLimit     = 256                    // Maximum number of unique blocks a peer may have announced
	blockLimit    = 64                     // Maximum number of unique blocks a peer may have delivered
)

var (
	errTerminated = errors.New("terminated")
)

// blockRetrievalFn is a callback type for retrieving a block from the local chain.
type blockRetrievalFn func(common.Hash) *types.Block

// blockRequesterFn is a callback type for sending a block retrieval request.
type blockRequesterFn func(common.Hash) error

// headerVerifierFn is a callback type to verify a block's header for fast propagation.
type headerVerifierFn func(header *types.Header) error

// blockBroadcasterFn is a callback type for broadcasting a block to connected peers.
type blockBroadcasterFn func(block *types.Block, propagate bool)

// chainHeightFn is a callback type to retrieve the current chain height.
type chainHeightFn func() uint64

// chainInsertFn is a callback type to insert a batch of blocks into the local chain.
type chainInsertFn func(types.Blocks) error

// peerDropFn is a callback type for dropping a peer detected as malicious.
type peerDropFn func(id string)

// announce is the hash notification of the availability of a new block in the
// network.
type announce struct {
	hash   common.Hash   // Hash of the block being announced
	number uint64        // Number of the block being announced (0 = unknown | old protocol)
	header *types.Header // Header of the block partially reassembled (new protocol)
	time   time.Time     // Timestamp of the announcement

	origin string // Identifier of the peer originating the notification

	fetchBlock blockRequesterFn
}

// inject represents a schedules import operation.
type inject struct {
	origin string
	block  *types.Block
}

// Fetcher is responsible for accumulating block announcements from various peers
// and scheduling them for retrieval.
type Fetcher struct {
	// Various event channels
	notify chan *announce
	inject chan *inject

	done chan common.Hash
	quit chan struct{}

	// Announce states
	// announced: 保留来自不同节点的同一区块hash，等待随机选取一个节点来获取该区块的header和body
	// fetching: 从announced中随机选取一个节点来获取header，放入fetching中
	// fetched: 获取到header后，等待获取body，放入fetched中
	// completing: 从fetched中执行任务，开始获取区块的body，放入到completing中
	announces map[string]int              // Per peer announce counts to prevent memory exhaustion
	announced map[common.Hash][]*announce // Announced blocks, scheduled for fetching。
	fetching  map[common.Hash]*announce   // Announced blocks, currently fetching

	// Block cache
	queue  *prque.Prque            // Queue containing the import operations (block number sorted)
	queues map[string]int          // Per peer block counts to prevent memory exhaustion
	queued map[common.Hash]*inject // Set of already queued blocks (to dedupe imports)

	// Callbacks
	getBlock       blockRetrievalFn   // Retrieves a block from the local chain
	verifyHeader   headerVerifierFn   // Checks if a block's headers have a valid proof of work
	broadcastBlock blockBroadcasterFn // Broadcasts a block to connected peers
	chainHeight    chainHeightFn      // Retrieves the current chain's height
	insertChain    chainInsertFn      // Injects a batch of blocks into the chain
	dropPeer       peerDropFn         // Drops a peer for misbehaving
}

// New creates a block fetcher to retrieve blocks based on hash announcements.
func New(getBlock blockRetrievalFn,
	verifyHeader headerVerifierFn,
	broadcastBlock blockBroadcasterFn,
	chainHeight chainHeightFn,
	insertChain chainInsertFn,
	dropPeer peerDropFn) *Fetcher {
	return &Fetcher{
		notify:         make(chan *announce),
		inject:         make(chan *inject),
		done:           make(chan common.Hash),
		quit:           make(chan struct{}),
		announces:      make(map[string]int),
		announced:      make(map[common.Hash][]*announce),
		fetching:       make(map[common.Hash]*announce),
		queue:          prque.New(),
		queues:         make(map[string]int),
		queued:         make(map[common.Hash]*inject),
		getBlock:       getBlock,
		verifyHeader:   verifyHeader,
		broadcastBlock: broadcastBlock,
		chainHeight:    chainHeight,
		insertChain:    insertChain,
		dropPeer:       dropPeer,
	}
}

// Start boots up the announcement based synchroniser, accepting and processing
// hash notifications and block fetches until termination requested.
func (f *Fetcher) Start() {
	logging.Debug("Fetcher start")
	go f.loop()
}

// Stop terminates the announcement based synchroniser, canceling all pending
// operations.
func (f *Fetcher) Stop() {
	close(f.quit)
}

// Notify announces the fetcher of the potential availability of a new block in
// the network.
func (f *Fetcher) Notify(peer string, hash common.Hash, number uint64, time time.Time,
	blockFetcher blockRequesterFn) error {
	logging.Debug("Fetch Notify: ", "number", number, "pid", peer)
	block := &announce{
		hash:       hash,
		number:     number,
		time:       time,
		origin:     peer,
		fetchBlock: blockFetcher,
	}
	select {
	case f.notify <- block:
		return nil
	case <-f.quit:
		return errTerminated
	}
}

// Enqueue tries to fill gaps the fetcher's future import queue.
func (f *Fetcher) Enqueue(peer string, block *types.Block) error {
	op := &inject{
		origin: peer,
		block:  block,
	}
	select {
	case f.inject <- op:
		return nil
	case <-f.quit:
		return errors.New("terminated")
	}
}

// Loop is the main fetcher loop, checking and processing various notification
// events.
func (f *Fetcher) loop() {
	// Iterate the block fetching until a quit is requested
	fetchTimer := time.NewTimer(0)
	//completeTimer := time.NewTimer(0)

	for {
		// Clean up any expired block fetches
		for hash, announce := range f.fetching {
			if time.Since(announce.time) > fetchTimeout {
				f.forgetHash(hash)
			}
		}
		// Import any queued blocks that could potentially fit
		height := f.chainHeight()
		for !f.queue.Empty() {
			op := f.queue.PopItem().(*inject)
			hash := op.block.Hash()

			// If too high up the chain or phase, continue later
			number := op.block.NumberU64()
			if number > height+1 {
				f.queue.Push(op, -float32(number))
				//if f.queueChangeHook != nil {
				//	f.queueChangeHook(hash, true)
				//}
				break
			}
			// Otherwise if fresh and still unknown, try and import
			if number+maxUncleDist < height || f.getBlock(hash) != nil {
				f.forgetBlock(hash)
				continue
			}
			f.insert(op.origin, op.block)
		}

		// Wait for an outside event to occur
		select {
		case <-f.quit:
			// Fetcher terminating, abort all operations
			return

		case notification := <-f.notify:
			// A block was announced, make sure the peer isn't DOSing us
			//propAnnounceInMeter.Mark(1)
			logging.Debug("Notification: ", "number", notification.number)
			count := f.announces[notification.origin] + 1
			if count > hashLimit {
				logging.Debug("Peer exceeded outstanding announces: ", "origin", notification.origin, "limit", hashLimit)
				//propAnnounceDOSMeter.Mark(1)
				break
			}

			// If we have a valid block number, check that it's potentially useful
			if notification.number > 0 {
				if dist := int64(notification.number) - int64(f.chainHeight()); dist < -maxUncleDist || dist > maxQueueDist {
					logging.Debug("Peer discarded announcement", "number", notification.number, "distance", dist)
					//propAnnounceDropMeter.Mark(1)
					break
				}
			}

			// All is well, schedule the announce if block's not yet downloading
			if _, ok := f.fetching[notification.hash]; ok {
				break
			}

			f.announces[notification.origin] = count
			f.announced[notification.hash] = append(f.announced[notification.hash], notification)

			if len(f.announced) == 1 {
				f.rescheduleFetch(fetchTimer)
			}

		case op := <-f.inject:
			//A direct block insertion was requested, try and fill any pending gaps
			//propBroadcastInMeter.Mark(1)
			f.enqueue(op.origin, op.block)

		case hash := <-f.done:
			// A pending import finished, remove all traces of the notification
			f.forgetHash(hash)
			f.forgetBlock(hash)

		case <-fetchTimer.C:
			// At least one block's timer ran out, check for needing retrieval
			request := make(map[string][]common.Hash)

			for hash, announces := range f.announced {
				if time.Since(announces[0].time) > arriveTimeout-gatherSlack {
					// Pick a random peer to retrieve from, reset all others
					announce := announces[rand.Intn(len(announces))]
					f.forgetHash(hash)

					// If the block still didn't arrive, queue for fetching
					if f.getBlock(hash) == nil {
						request[announce.origin] = append(request[announce.origin], hash)
						f.fetching[hash] = announce
					}
				}
			}
			// Send out all block header requests
			for peer, hashes := range request {
				logging.Debug("--------Fetching scheduled headers", "peer", peer)

				// Create a closure of the fetch and schedule in on a new thread
				fetchBlock, hashes := f.fetching[hashes[0]].fetchBlock, hashes
				go func(p string) {
					for _, hash := range hashes {
						//headerFetchMeter.Mark(1)
						err := fetchBlock(hash) // Suboptimal, but protocol doesn't allow batch header retrievals
						if err != nil {
							logging.Warn("send requestBlock failed", "toPeer", p, "err", err)
						}
					}
				}(peer)
			}
			// Schedule the next fetch if blocks are still pending
			f.rescheduleFetch(fetchTimer)
		}
	}
}

// enqueue schedules a new future import operation, if the block to be imported
// has not yet been seen.
func (f *Fetcher) enqueue(peer string, block *types.Block) {
	hash := block.Hash()

	// Ensure the peer isn't DOSing us
	count := f.queues[peer] + 1
	if count > blockLimit {
		logging.Debug("Discarded propagated block, exceeded allowance: ", "height", block.Number(), "pid", peer, "limit", blockLimit)
		//propBroadcastDOSMeter.Mark(1)
		f.forgetHash(hash)
		return
	}

	// Discard any past or too distant blocks
	if dist := int64(block.NumberU64()) - int64(f.chainHeight()); dist < -maxUncleDist || dist > maxQueueDist {
		logging.Debug("Discarded propagated block, too far away: ", "height", block.Number(), "pid", peer, "distance", dist)
		//propBroadcastDropMeter.Mark(1)
		f.forgetHash(hash)
		return
	}

	// Schedule the block for future importing
	if _, ok := f.queued[hash]; !ok {
		op := &inject{
			origin: peer,
			block:  block,
		}
		f.queues[peer] = count
		f.queued[hash] = op
		f.queue.Push(op, -float32(block.NumberU64())) // 越新的区块优先级越低，达到排序的目的

		logging.Debug("Queued propagated block: ", "number", block.Number(), "queued", f.queue.Size(), "pid", peer)
	}
}

// insert spawns a new goroutine to run a block insertion into the chain. If the
// block's number is at the same height as the current import phase, it updates
// the phase states accordingly.
func (f *Fetcher) insert(peer string, block *types.Block) {
	hash := block.Hash()

	// Run the import on a new thread
	logging.Debug("Importing propagated block: ", "pid", peer, "height", block.Number())
	go func() {
		defer func() { f.done <- hash }()

		// If the parent's unknown, abort insertion
		parent := f.getBlock(block.ParentHash())
		if parent == nil {
			logging.Debug("Unknown parent of propagated block", "pid", peer, "height", block.Number(), "parent", block.ParentHash())
			return
		}
		// Quickly validate the header and propagate the block if it passes
		switch err := f.verifyHeader(block.Header()); err {
		case nil:
			// All ok, quickly propagate to our peers
			//propBroadcastOutTimer.UpdateSince(block.ReceivedAt)
			go f.broadcastBlock(block, true)

		case consensus.ErrFutureBlock:
			// Weird future block, don't fail, but neither propagate

		case consensus.ErrExistCanonical:
			// exist another block in canonical chain, don't fail, but neither propagate
		case consensus.ErrUnknownParentState:
			// parent's state doesn't exist, don't fail, but neither propagate
			logging.Error("err", err)
		default:
			// Something went very wrong, drop the peer
			logging.Debug("Propagated block verification failed", "number", block.Number(), "pid", peer, "err", err)
			f.dropPeer(peer)
			return
		}
		// Run the actual import and log any issues
		if err := f.insertChain(types.Blocks{block}); err != nil {
			logging.Debug("Propagated block import failed", "number", block.Number(), "pid", peer, "err", err)
			return
		}
		// If import succeeded, broadcast the block
		//propAnnounceOutTimer.UpdateSince(block.ReceivedAt)
		go f.broadcastBlock(block, false)
	}()
}

// forgetHash removes all traces of a block announcement from the fetcher's
// internal state.
func (f *Fetcher) forgetHash(hash common.Hash) {
	// Remove all pending announces and decrement DOS counters
	for _, announce := range f.announced[hash] {
		f.announces[announce.origin]--
		if f.announces[announce.origin] == 0 {
			delete(f.announces, announce.origin)
		}
	}
	delete(f.announced, hash)

	// Remove any pending fetches and decrement the DOS counters
	if announce := f.fetching[hash]; announce != nil {
		f.announces[announce.origin]--
		if f.announces[announce.origin] == 0 {
			delete(f.announces, announce.origin)
		}
		delete(f.fetching, hash)
	}
}

// forgetBlock removes all traces of a queued block from the fetcher's internal
// state.
func (f *Fetcher) forgetBlock(hash common.Hash) {
	if insert := f.queued[hash]; insert != nil {
		f.queues[insert.origin]--
		if f.queues[insert.origin] == 0 {
			delete(f.queues, insert.origin)
		}
		delete(f.queued, hash)
	}
}

// rescheduleFetch resets the specified fetch timer to the next announce timeout.
func (f *Fetcher) rescheduleFetch(fetch *time.Timer) {
	// Short circuit if no blocks are announced
	if len(f.announced) == 0 {
		return
	}
	// Otherwise find the earliest expiring announcement
	earliest := time.Now()
	for _, announces := range f.announced {
		if earliest.After(announces[0].time) {
			earliest = announces[0].time
		}
	}
	fetch.Reset(arriveTimeout - time.Since(earliest))
}
