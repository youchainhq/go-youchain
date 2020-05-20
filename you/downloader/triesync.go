// Copyright 2017 The go-ethereum Authors
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
	"fmt"
	"hash"
	"sync"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/rawdb"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/trie"
	"github.com/youchainhq/go-youchain/youdb"
	"golang.org/x/crypto/sha3"
)

// trieReq represents a batch of trie fetch requests grouped together into
// a single data retrieval network packet.
type trieReq struct {
	items    []common.Hash             // Hashes of the state items to download
	tasks    map[common.Hash]*trieTask // Download tasks to track previous attempts
	timeout  time.Duration             // Maximum round trip time for this to complete
	timer    *time.Timer               // Timer to fire when the RTT timeout expires
	peer     *peerConnection           // Peer that we're requesting from
	response [][]byte                  // Response data of the peer (nil for timeouts)
	dropped  bool                      // Flag whether the peer dropped off early
}

// timedOut returns if this request timed out.
func (req *trieReq) timedOut() bool {
	return req.response == nil
}

// stateSyncStats is a collection of progress stats to report during a state trie
// sync to RPC requests as well as to display in user logs.
type stateSyncStats struct {
	processed  uint64 // Number of state entries processed
	duplicate  uint64 // Number of state entries downloaded twice
	unexpected uint64 // Number of non-requested state entries received
	pending    uint64 // Number of still pending state entries
}

func (d *Downloader) FetchVldTrie(root common.Hash) error {
	vldSync := d.syncVldTrie(root)
	return vldSync.Wait()
}

func (d *Downloader) fetchStakingTrie(root common.Hash) error {
	if root == (common.Hash{}) {
		return nil
	}
	sSync := d.syncStakingTrie(root)
	return sSync.Wait()
}

// syncState starts downloading state with the given root hash.
func (d *Downloader) syncState(root common.Hash) *trieSync {
	backingDb := d.lightchain.TrieBackingDb(types.KindState)
	task := newTrieSync(d, types.KindState, backingDb, state.NewStateSync(root, backingDb))
	return d.launchTrieSync(task)
}

// syncVldTrie starts downloading validator trie with the given root hash
func (d *Downloader) syncVldTrie(root common.Hash) *trieSync {
	return d.commonSyncTrie(types.KindValidator, root)
}

// syncStakingTrie starts downloading staking trie with the given root hash
func (d *Downloader) syncStakingTrie(root common.Hash) *trieSync {
	return d.commonSyncTrie(types.KindStaking, root)
}

// syncCht starts downloading cht with the given root hash.
func (d *Downloader) syncCht(root common.Hash) *trieSync {
	return d.commonSyncTrie(types.KindCht, root)
}

// syncBlt starts downloading blt with the given root hash.
func (d *Downloader) syncBlt(root common.Hash) *trieSync {
	return d.commonSyncTrie(types.KindBlt, root)
}

// commonSyncTrie syncs a specific kind of trie with the given root hash
func (d *Downloader) commonSyncTrie(kind types.TrieKind, root common.Hash) *trieSync {
	backingDb := d.lightchain.TrieBackingDb(kind)
	task := newTrieSync(d, kind, backingDb, trie.NewSync(root, backingDb, nil))
	return d.launchTrieSync(task)
}

func (d *Downloader) launchTrieSync(task *trieSync) *trieSync {
	select {
	case d.trieSyncStart <- task: //create sync task and wait for running
	case <-d.quitCh:
		task.err = errCancelTrieFetch
		close(task.done)
	}
	return task
}

// trieFetcher manages the active trie sync and accepts requests
// on its behalf.
func (d *Downloader) trieFetcher() {
	for {
		select {
		case task := <-d.trieSyncStart: //获得同步任务，开始同步，直到执行完所有的任务
			d.runTrieSync(task)
		case <-d.trieCh:
			// Ignore state responses while no sync is running.
		case <-d.quitCh:
			return
		}
	}
}

// runTrieSync runs a trie synchronisation until it completes.
func (d *Downloader) runTrieSync(s *trieSync) {
	var (
		active   = make(map[string]*trieReq) // Currently in-flight requests
		finished []*trieReq                  // Completed or failed requests
		timeout  = make(chan *trieReq)       // Timed out active requests
	)
	defer func() {
		// Cancel active request timers on exit. Also set peers to idle so they're
		// available for the next sync.
		for _, req := range active {
			req.timer.Stop()
			req.peer.SetNodeDataIdle(len(req.items))
		}
	}()
	// Run the trie sync.
	go s.run()
	defer s.Cancel()

	// Listen for peer departure events to cancel assigned tasks
	peerDrop := make(chan *peerConnection, 1024)
	peerSub := s.d.peers.SubscribePeerDrops(peerDrop)
	defer peerSub.Unsubscribe()

	for {
		// Enable sending of the first buffered element if there is one.
		var (
			deliverReq   *trieReq
			deliverReqCh chan *trieReq
		)
		if len(finished) > 0 {
			deliverReq = finished[0]
			deliverReqCh = s.deliver
		}

		select {
		case <-s.done:
			logging.Trace("trie sync done", "kind", s.kind, "err", s.err)
			return

		// Send the next finished request to the current sync:
		case deliverReqCh <- deliverReq:
			// Shift out the first request, but also set the emptied slot to nil for GC
			copy(finished, finished[1:])
			finished[len(finished)-1] = nil
			finished = finished[:len(finished)-1]

		// Handle incoming state packs:
		case pack := <-d.trieCh:
			// Discard any data not requested (or previously timed out)
			req := active[pack.PeerId()]
			if req == nil {
				logging.Debug("Unrequested node data", "peer", pack.PeerId(), "len", pack.Items())
				continue
			}
			// Finalize the request and queue up for processing
			req.timer.Stop()
			req.response = pack.(*triePack).nodes

			finished = append(finished, req)
			delete(active, pack.PeerId())

		// Handle dropped peer connections:
		case p := <-peerDrop:
			// Skip if no request is currently pending
			req := active[p.id]
			if req == nil {
				continue
			}
			// Finalize the request and queue up for processing
			req.timer.Stop()
			req.dropped = true

			finished = append(finished, req)
			delete(active, p.id)

		// Handle timed-out requests:
		case req := <-timeout:
			// If the peer is already requesting something else, ignore the stale timeout.
			// This can happen when the timeout and the delivery happens simultaneously,
			// causing both pathways to trigger.
			if active[req.peer.id] != req {
				continue
			}
			// Move the timed out data back into the download queue
			finished = append(finished, req)
			delete(active, req.peer.id)

		// Track outgoing state requests:
		case req := <-d.trackTrieReq:
			// If an active request already exists for this peer, we have a problem. In
			// theory the trie node schedule must never assign two requests to the same
			// peer. In practice however, a peer might receive a request, disconnect and
			// immediately reconnect before the previous times out. In this case the
			// first request is never honored, alas we must not silently overwrite it,
			// as that causes valid requests to go missing and sync to get stuck.
			if oldReq := active[req.peer.id]; oldReq != nil {
				logging.Warn("Busy peer assigned new state fetch", "peer", oldReq.peer.id)

				// Make sure the previous one doesn't get silently lost
				oldReq.timer.Stop()
				oldReq.dropped = true

				finished = append(finished, oldReq)
			}
			// Start a timer to notify the sync loop if the peer stalled.
			req.timer = time.AfterFunc(req.timeout, func() {
				select {
				case timeout <- req: //请求超时时，发送信号，将此节点的请求从active中移除
				case <-s.done:
					// Prevent leaking of timer goroutines in the unlikely case where a
					// timer is fired just before exiting runTrieSync.
				}
			})
			active[req.peer.id] = req
		}
	}
}

// trieSync schedules requests for downloading a particular Merkle Patrica trie defined
// by a given trie root.
type trieSync struct {
	d *Downloader // Downloader instance to access and manage current peerset

	kind      types.TrieKind
	backingDb youdb.Database            // the trie backing database
	sched     *trie.Sync                // trie sync scheduler defining the tasks
	keccak    hash.Hash                 // Keccak256 hasher to verify deliveries with
	tasks     map[common.Hash]*trieTask // Set of tasks currently queued for retrieval

	numUncommitted   int
	bytesUncommitted int

	deliver    chan *trieReq // Delivery channel multiplexing peer responses
	cancel     chan struct{} // Channel to signal a termination request
	cancelOnce sync.Once     // Ensures cancel only ever gets called once
	done       chan struct{} // Channel to signal termination completion
	err        error         // Any error hit during sync (set before completion)
}

// trieTask represents a single trie node download task, containing a set of
// peers already attempted retrieval from to detect stalled syncs and abort.
type trieTask struct {
	attempts map[string]struct{}
}

// newTrieSync creates a new trie download scheduler. This method does not
// yet start the sync. The user needs to call run to initiate.
func newTrieSync(d *Downloader, kind types.TrieKind, db youdb.Database, scheduler *trie.Sync) *trieSync {
	return &trieSync{
		d:         d,
		kind:      kind,
		backingDb: db,
		sched:     scheduler,
		keccak:    sha3.NewLegacyKeccak256(),
		tasks:     make(map[common.Hash]*trieTask),
		deliver:   make(chan *trieReq),
		cancel:    make(chan struct{}),
		done:      make(chan struct{}),
	}
}

// run starts the task assignment and response processing loop, blocking until
// it finishes, and finally notifying any goroutines waiting for the loop to
// finish.
func (s *trieSync) run() {
	s.err = s.loop()
	close(s.done)
}

// Wait blocks until the sync is done or canceled.
func (s *trieSync) Wait() error {
	<-s.done
	return s.err
}

// Cancel cancels the sync and waits until it has shut down.
func (s *trieSync) Cancel() error {
	s.cancelOnce.Do(func() { close(s.cancel) })
	return s.Wait()
}

// loop is the main event loop of a trie sync. It it responsible for the
// assignment of new tasks to peers (including sending it to them) as well as
// for the processing of inbound data. Note, that the loop does not directly
// receive data from peers, rather those are buffered up in the downloader and
// pushed here async. The reason is to decouple processing from data receipt
// and timeouts.
func (s *trieSync) loop() (err error) {
	// Listen for new peer events to assign tasks to them
	newPeer := make(chan *peerConnection, 1024)
	peerSub := s.d.peers.SubscribeNewPeers(newPeer)
	defer peerSub.Unsubscribe()
	defer func() {
		cerr := s.commit(true)
		if err == nil {
			err = cerr
		}
	}()

	// Keep assigning new tasks until the sync completes or aborts
	for s.sched.Pending() > 0 {
		if err = s.commit(false); err != nil {
			return err
		}
		s.assignTasks()
		// Tasks assigned, wait for something to happen
		select {
		case <-newPeer:
			// New peer arrived, try to assign it download tasks

		case <-s.cancel:
			logging.Error("s.cancel errCancelTrieFetch")
			return errCancelTrieFetch

		case <-s.d.cancelCh:
			logging.Error("s.d.cancelCh errCancelTrieFetch")
			return errCanceled

		case req := <-s.deliver:
			// Response, disconnect or timeout triggered, drop the peer if stalling
			logging.Trace("Received node data response", "peer", req.peer.id, "count", len(req.response), "dropped", req.dropped, "timeout", !req.dropped && req.timedOut())
			if len(req.items) <= 2 && !req.dropped && req.timedOut() {
				// 2 items are the minimum requested, if even that times out, we've no use of
				// this peer at the moment.
				logging.Warn("Stalling state sync, dropping peer", "peer", req.peer.id)
				s.d.dropPeer(req.peer.id)
			}
			// Process all the received blobs and check for stale delivery
			delivered, err := s.process(req)
			if err != nil {
				logging.Warn("Node data write error", "err", err)
				return err
			}
			req.peer.SetNodeDataIdle(delivered)
		}
	}
	return nil
}

func (s *trieSync) commit(force bool) error {
	if !force && s.bytesUncommitted < youdb.IdealBatchSize {
		return nil
	}
	start := time.Now()
	b := s.backingDb.NewBatch()
	if written, err := s.sched.Commit(b); written == 0 || err != nil {
		return err
	}
	if err := b.Write(); err != nil {
		return fmt.Errorf("DB write error: %v", err)
	}
	logging.Debug("trie committed", "kind", s.kind, "written", s.numUncommitted)
	if s.kind == types.KindState {
		s.updateStats(s.numUncommitted, 0, 0, time.Since(start))
	}
	s.numUncommitted = 0
	s.bytesUncommitted = 0
	return nil
}

// assignTasks attempts to assign new tasks to all idle peers, either from the
// batch currently being retried, or fetching new data from the trie sync itself.
func (s *trieSync) assignTasks() {
	// Iterate over all idle peers and try to assign them state fetches
	peers, _ := s.d.peers.NodeDataIdlePeers()
	for _, p := range peers {
		// Assign a batch of fetches proportional to the estimated latency/bandwidth
		cap := p.NodeDataCapacity(s.d.requestRTT())
		req := &trieReq{peer: p, timeout: s.d.requestTTL()}
		s.fillTasks(cap, req)

		// If the peer was assigned tasks to fetch, send the network request
		if len(req.items) > 0 {
			logging.Info("Requesting new batch of data", "kind", s.kind, "count", len(req.items), "peer", p.id)
			select {
			case s.d.trackTrieReq <- req: //记录当前同步任务，处理超时
				if err := req.peer.FetchNodeData(s.kind, req.items); err != nil {
					logging.Error("FetchNodeData err", err)
				}
			case <-s.cancel:
			case <-s.d.cancelCh:
			}
		}
	}
}

// fillTasks fills the given request object with a maximum of n state download
// tasks to send to the remote peer.
func (s *trieSync) fillTasks(n int, req *trieReq) {
	// Refill available tasks from the scheduler.
	if len(s.tasks) < n {
		new := s.sched.Missing(n - len(s.tasks))
		for _, hash := range new {
			s.tasks[hash] = &trieTask{make(map[string]struct{})}
		}
	}
	// Find tasks that haven't been tried with the request's peer.
	req.items = make([]common.Hash, 0, n)
	req.tasks = make(map[common.Hash]*trieTask, n)
	for hash, t := range s.tasks {
		// Stop when we've gathered enough requests
		if len(req.items) == n {
			break
		}
		// Skip any requests we've already tried from this peer
		if _, ok := t.attempts[req.peer.id]; ok {
			continue
		}
		// Assign the request to this peer
		t.attempts[req.peer.id] = struct{}{}
		req.items = append(req.items, hash)
		req.tasks[hash] = t
		delete(s.tasks, hash)
	}
}

// process iterates over a batch of delivered state data, injecting each item
// into a running state sync, re-queuing any items that were requested but not
// delivered. Returns whether the peer actually managed to deliver anything of
// value, and any error that occurred.
func (s *trieSync) process(req *trieReq) (int, error) {
	// Collect processing stats and update progress if valid data was received
	duplicate, unexpected, successful := 0, 0, 0

	defer func(start time.Time) {
		if s.kind == types.KindState && (duplicate > 0 || unexpected > 0) {
			s.updateStats(0, duplicate, unexpected, time.Since(start))
		}
	}(time.Now())

	// Iterate over all the delivered data and inject one-by-one into the trie
	for _, blob := range req.response {
		_, hash, err := s.processNodeData(blob)
		switch err {
		case nil:
			s.numUncommitted++
			s.bytesUncommitted += len(blob)
			successful++
		case trie.ErrNotRequested:
			unexpected++
		case trie.ErrAlreadyProcessed:
			duplicate++
		default:
			return successful, fmt.Errorf("invalid trie node %s: %v", hash.TerminalString(), err)
		}
		if _, ok := req.tasks[hash]; ok {
			delete(req.tasks, hash)
		}
	}
	// Put unfulfilled tasks back into the retry queue
	npeers := s.d.peers.Len()
	for hash, task := range req.tasks {
		// If the node did deliver something, missing items may be due to a protocol
		// limit or a previous timeout + delayed delivery. Both cases should permit
		// the node to retry the missing items (to avoid single-peer stalls).
		if len(req.response) > 0 || req.timedOut() {
			delete(task.attempts, req.peer.id)
		}
		// If we've requested the node too many times already, it may be a malicious
		// sync where nobody has the right data. Abort.
		if len(task.attempts) >= npeers {
			return successful, fmt.Errorf("state node %s failed with all peers (%d tries, %d peers)", hash.TerminalString(), len(task.attempts), npeers)
		}
		// Missing item, place into the retry queue.
		s.tasks[hash] = task
	}
	return successful, nil
}

// processNodeData tries to inject a trie node data blob delivered from a remote
// peer into the state trie, returning whether anything useful was written or any
// error occurred.
func (s *trieSync) processNodeData(blob []byte) (bool, common.Hash, error) {
	res := trie.SyncResult{Data: blob}
	s.keccak.Reset()
	s.keccak.Write(blob)
	s.keccak.Sum(res.Hash[:0])
	committed, _, err := s.sched.Process([]trie.SyncResult{res})
	return committed, res.Hash, err
}

// updateStats bumps the various state sync progress counters and displays a log
// message for the user to see.
func (s *trieSync) updateStats(written, duplicate, unexpected int, duration time.Duration) {
	s.d.syncStatsLock.Lock()
	defer s.d.syncStatsLock.Unlock()

	s.d.syncStatsState.pending = uint64(s.sched.Pending())
	s.d.syncStatsState.processed += uint64(written)
	s.d.syncStatsState.duplicate += uint64(duplicate)
	s.d.syncStatsState.unexpected += uint64(unexpected)

	if written > 0 || duplicate > 0 || unexpected > 0 {
		logging.Info("Imported new state entries", "count", written, "elapsed", common.PrettyDuration(duration), "processed", s.d.syncStatsState.processed, "pending", s.d.syncStatsState.pending, "retry", len(s.tasks), "duplicate", s.d.syncStatsState.duplicate, "unexpected", s.d.syncStatsState.unexpected)
	}
	if written > 0 {
		rawdb.WriteFastTrieProgress(s.backingDb, s.d.syncStatsState.processed)
	}
}
