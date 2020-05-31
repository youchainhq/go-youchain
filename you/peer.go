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
	"errors"
	"fmt"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/consensus/ucon"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/p2p"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set"
)

const (
	maxKnownTxs       = 32768 // Maximum transactions hashes to keep in the known list (prevent DOS)
	maxKnownConsensus = 32768
	maxKnownBlocks    = 1024 // Maximum block hashes to keep in the known list (prevent DOS)

	// maxQueuedTxs is the maximum number of transaction lists to queue up before
	// dropping broadcasts. This is a sensitive number as a transaction list might
	// contain a single transaction, or thousands.
	maxQueuedTxs       = 128
	maxQueuedConsensus = 128
)

const (
	// maxQueuedProps is the maximum number of block propagations to queue up before
	// dropping broadcasts. There's not much point in queueing stale blocks, so a few
	// that might cover uncles should be enough.
	maxQueuedProps = 4

	// maxQueuedAnns is the maximum number of block announcements to queue up before
	// dropping broadcasts. Similarly to block propagations, there's no point to queue
	// above some healthy uncle limit, so use that.
	maxQueuedAnns = 4

	handshakeTimeout = 5 * time.Second
)

type propEvent struct {
	block *types.Block
}

type peer struct {
	id string

	*p2p.Peer
	rw p2p.MsgReadWriter

	version  int         // Protocol version negotiated
	forkDrop *time.Timer // Timed connection dropper if forks aren't validated in time

	head   common.Hash
	number *big.Int
	origin *big.Int // Number starting full sync
	lock   sync.RWMutex

	knownTxs        mapset.Set // Set of transaction hashes known to be known by this peer
	knownBlocks     mapset.Set // Set of block hashes known to be known by this peer
	knownConsensus  mapset.Set
	queuedTxs       chan []*types.Transaction // Queue of transactions to broadcast to the peer
	queuedProps     chan *propEvent           // Queue of blocks to broadcast to the peer
	queuedAnns      chan *types.Block         // Queue of blocks to announce to the peer
	queuedConsensus chan *ucon.MessageEvent
	term            chan struct{} // Termination channel to stop the broadcaster
	msgSequence     int64
}

func newPeer(version int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	peer := &peer{
		Peer:            p,
		rw:              rw,
		version:         version,
		id:              fmt.Sprintf("%s-%s-%x", p.Name(), p.Node().IP(), p.ID().Bytes()[:8]), //todo fixme change back to id
		knownTxs:        mapset.NewSet(),
		knownBlocks:     mapset.NewSet(),
		knownConsensus:  mapset.NewSet(),
		queuedTxs:       make(chan []*types.Transaction, maxQueuedTxs),
		queuedProps:     make(chan *propEvent, maxQueuedProps),
		queuedAnns:      make(chan *types.Block, maxQueuedAnns),
		queuedConsensus: make(chan *ucon.MessageEvent, maxQueuedConsensus),
		term:            make(chan struct{}),
	}
	return peer
}

func (p *peer) Origin() (number *big.Int) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	return new(big.Int).Set(p.origin)
}

// Head retrieves a copy of the current head hash of the peer.
func (p *peer) Head() (hash common.Hash, number *big.Int) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	copy(hash[:], p.head[:])
	if p.number != nil {
		return hash, new(big.Int).Set(p.number)
	}
	return hash, nil
}

// SetHead updates the head hash of the peer.
func (p *peer) SetHead(hash common.Hash, number *big.Int) {
	p.lock.Lock()
	defer p.lock.Unlock()

	copy(p.head[:], hash[:])
	if p.number == nil {
		p.number = number
	} else {
		p.number.Set(number)
	}
}

// broadcast is a write loop that multiplexes block propagations, announcements
// and transaction broadcasts into the remote peer. The goal is to have an async
// writer that does not lock up node internals.
func (p *peer) broadcast() {
	for {
		select {
		case ev, ok := <-p.queuedConsensus:
			if !ok {
				return
			}
			if err := p.SendConsensus(ev); err != nil {
				return
			}
		case txs := <-p.queuedTxs:
			if err := p.SendTransactions(txs); err != nil {
				return
			}
			logging.Info("Broadcast transactions", "count", len(txs))

		case prop := <-p.queuedProps:
			if err := p.SendNewBlock(prop.block); err != nil {
				return
			}
			logging.Info("Propagated block", "number", prop.block.Number(), "hash", prop.block.Hash().String())

		case block := <-p.queuedAnns:
			if err := p.SendNewBlockHashes([]common.Hash{block.Hash()}, []uint64{block.NumberU64()}); err != nil {
				return
			}
			logging.Trace("Announced block", "number", block.Number(), "hash", block.Hash().String())

		case <-p.term:
			return
		}
	}
}

// MarkTransaction marks a transaction as known for the peer, ensuring that it
// will never be propagated to this particular peer.
func (p *peer) MarkTransaction(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownTxs.Cardinality() >= maxKnownTxs {
		p.knownTxs.Pop()
	}
	p.knownTxs.Add(hash)
}

// SendTransactions sends transactions to the peer and includes the hashes
// in its transaction hash set for future reference.
func (p *peer) SendTransactions(txs types.Transactions) error {
	for _, tx := range txs {
		p.knownTxs.Add(tx.Hash())
	}
	if err := p2p.Send(p.rw, TxMsg, txs); err != nil {
		logging.Error("p2p send TxMsg failed", "pid", p.id, "txs", len(txs), "err", err)
	}
	return nil
}

func (p *peer) SendConsensus(ev *ucon.MessageEvent) error {
	evb, err := rlp.EncodeToBytes(ev)
	if err != nil {
		return err
	}
	hash := crypto.Keccak256Hash(evb)

	if p.knownConsensus.Cardinality() >= maxKnownConsensus {
		p.knownConsensus.Pop()
	}
	p.knownConsensus.Add(hash)

	return p2p.Send(p.rw, ConsensusMsg, ev.Payload)

}

// AsyncSendTransactions queues list of transactions propagation to a remote
// peer. If the peer's broadcast queue is full, the event is silently dropped.
func (p *peer) AsyncSendTransactions(txs []*types.Transaction) {
	select {
	case p.queuedTxs <- txs:
		for _, tx := range txs {
			p.knownTxs.Add(tx.Hash())
		}
	default:
		logging.Debug("Dropping transaction propagation", "count", len(txs))
	}
}

// SendNewBlock propagates an entire block to a remote peer.
func (p *peer) SendNewBlock(block *types.Block) error {
	p.knownBlocks.Add(block.Hash())
	return p2p.Send(p.rw, NewBlockMsg, block)
}

// AsyncSendNewBlock queues an entire block for propagation to a remote peer. If
// the peer's broadcast queue is full, the event is silently dropped.
func (p *peer) AsyncSendNewBlock(block *types.Block) {
	logging.Info("AsyncSendNewBlock", "pid", p.id, "number", block.Number())
	select {
	case p.queuedProps <- &propEvent{block: block}:
		logging.Info("AsyncSendNewBlock put", "pid", p.id, "number", block.Number())
		p.knownBlocks.Add(block.Hash())
	default:
		logging.Debug("Dropping block propagation", "number", block.NumberU64(), "hash", block.Hash())
	}
}

// MarkBlock marks a block as known for the peer, ensuring that the block will
// never be propagated to this particular peer.
func (p *peer) MarkBlock(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known block hash
	for p.knownBlocks.Cardinality() >= maxKnownBlocks {
		p.knownBlocks.Pop()
	}
	p.knownBlocks.Add(hash)
}

func (p *peer) RequestGetBlock(hash common.Hash) error {
	return p2p.Send(p.rw, GetBlockMsg, hash)
}

// SendNewBlockHashes announces the availability of a number of blocks through
// a hash notification.
func (p *peer) SendNewBlockHashes(hashes []common.Hash, numbers []uint64) error {
	for _, hash := range hashes {
		p.knownBlocks.Add(hash)
	}
	request := make(NewBlockHashesData, len(hashes))
	for i := 0; i < len(hashes); i++ {
		request[i].Hash = hashes[i]
		request[i].Number = numbers[i]
	}
	return p2p.Send(p.rw, NewBlockHashMsg, request)
}

// AsyncSendNewBlockHash queues the availability of a block for propagation to a
// remote peer. If the peer's broadcast queue is full, the event is silently
// dropped.
func (p *peer) AsyncSendNewBlockHash(block *types.Block) {
	select {
	case p.queuedAnns <- block:
		p.knownBlocks.Add(block.Hash())
	default:
		logging.Debug("Dropping block announcement", "number", block.NumberU64(), "hash", block.Hash())
	}
}

// RequestBodies fetches a batch of blocks' bodies corresponding to the hashes
// specified.
func (p *peer) RequestBodies(hashes []common.Hash) error {
	p.Log().Debug("Fetching batch of block bodies", "count", len(hashes))
	return p2p.Send(p.rw, GetBlockBodiesMsg, hashes)
}

// SendBlockBodiesRLP sends a batch of block contents to the remote peer from
// an already RLP encoded format.
func (p *peer) SendBlockBodiesRLP(bodies []rlp.RawValue) error {
	return p2p.Send(p.rw, BlockBodiesMsg, bodies)
}

// RequestReceipts fetches a batch of transaction receipts from a remote node.
func (p *peer) RequestReceipts(hashes []common.Hash) error {
	p.Log().Debug("Fetching batch of receipts", "count", len(hashes))
	return p2p.Send(p.rw, GetReceiptsMsg, hashes)
}

// SendReceiptsRLP sends a batch of transaction receipts, corresponding to the
// ones requested from an already RLP encoded format.
func (p *peer) SendReceiptsRLP(receipts []rlp.RawValue) error {
	return p2p.Send(p.rw, ReceiptsMsg, receipts)
}

func (p *peer) AsyncSendConsensus(ev *ucon.MessageEvent) {
	select {
	case p.queuedConsensus <- ev:
	default:
		logging.Debug("Dropping Consensus Msg", "Msg Code", ev.Code, "Round", ev.Round)
	}
}

/**
send to msg queue, send by worker pool
*/
func (p *peer) SendToMsgQueue(msgcode uint64, data interface{}, mark string) {
	// seq := atomic.AddInt64(&p.msgSequence, 1)
	// now := time.Now()

	p2p.Send(p.rw, msgcode, data)

	// if err := p2p.Send(p.rw, msgcode, data); err != nil {
	// 	log.Info("msg", msgcode, "to", p, "seq:", seq, "using:", time.Now().Sub(now), "mark", mark, "err:", err)
	// } else {
	// 	log.Info("msg", msgcode, "to", p, "seq:", seq, "using:", time.Now().Sub(now), "mark", mark)
	// }

	// p.msgQueueWorkerPoolHighPriority.Queue(func() {
	// 	log.Trace("msg", msgcode, "to", p, "seq:", seq, "start:", now, "mark", mark)
	// 	if err := p2p.Send(p.rw, msgcode, data); err != nil {
	// 		log.Trace("msg", msgcode, "to", p, "seq:", seq, "using:", time.Now().Sub(now), "mark", mark, "err:", err)
	// 	} else {
	// 		log.Trace("msg", msgcode, "to", p, "seq:", seq, "using:", time.Now().Sub(now), "mark", mark)
	// 	}
	// }, 5*time.Second)
}

// Handshake executes the eth protocol handshake, negotiating version number,
// network IDs, difficulties, head and genesis blocks.
func (p *peer) Handshake(network uint64, height uint64, head common.Hash, origin uint64, genesis common.Hash) error {
	// Send out own handshake in a new thread

	logging.Info("ProtocolManager handle", "pid", p.String())

	errc := make(chan error, 2)
	var status statusData // safe to read after two values have been received from errc

	go func() {
		errc <- p2p.Send(p.rw, StatusMsg, &statusData{
			ProtocolVersion: uint32(p.version),
			Origin:          origin,
			Height:          height,
			NetworkId:       network,
			CurrentBlock:    head,
			GenesisBlock:    genesis,
		})
	}()
	go func() {
		errc <- p.readStatus(network, &status, genesis)
	}()
	timeout := time.NewTimer(handshakeTimeout)
	defer timeout.Stop()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errc:
			if err != nil {
				return err
			}
		case <-timeout.C:
			return p2p.DiscReadTimeout
		}
	}

	p.number, p.head, p.origin = new(big.Int).SetUint64(status.Height), status.CurrentBlock, new(big.Int).SetUint64(status.Origin)
	logging.Info("handshake with", "pid", p.id, "height", p.number, "hash", p.head.String(), "origin", p.origin)

	return nil
}

func (p *peer) readStatus(network uint64, status *statusData, genesis common.Hash) (err error) {
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Code != StatusMsg {
		return errResp(ErrNoStatusMsg, "first msg has code %x (!= %x)", msg.Code, StatusMsg)
	}
	if msg.Size > ProtocolMaxMsgSize {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	}
	// Decode the handshake and make sure everything matches
	if err := msg.Decode(&status); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	if status.GenesisBlock != genesis {
		return errResp(ErrGenesisBlockMismatch, "%x (!= %x)", status.GenesisBlock[:8], genesis[:8])
	}
	if status.NetworkId != network {
		return errResp(ErrNetworkIdMismatch, "%d (!= %d)", status.NetworkId, network)
	}
	if int(status.ProtocolVersion) != p.version {
		return errResp(ErrProtocolVersionMismatch, "%d (!= %d)", status.ProtocolVersion, p.version)
	}
	return nil
}

// String implements fmt.Stringer.
func (p *peer) String() string {
	return fmt.Sprintf("Peer %s [%s]", p.id,
		fmt.Sprintf("you/%2d", p.version),
	)
}

// close signals the broadcast goroutine to terminate.
func (p *peer) close() {
	close(p.term)

	logging.Info("peer close", "pid", p.id)
}

func (p *peer) RequestNodeData(kind types.TrieKind, hashes []common.Hash) error {
	request := GetNodeDataMsgData{Kind: kind, Hashes: hashes}
	return p2p.Send(p.rw, GetNodeDataMsg, request)
}

// SendNodeDataRLP sends a batch of arbitrary internal data, corresponding to the
// hashes requested.
func (p *peer) SendNodeData(data [][]byte) error {
	return p2p.Send(p.rw, NodeDataMsg, data)
}

func (p *peer) RequestHeadersByHash(origin common.Hash, amount int, skip int, reverse, light bool) error {
	logging.Debug("Fetching batch of headers", "count", amount, "fromhash", origin.String(), "skip", skip, "reverse", reverse, "light", light)
	return p2p.Send(p.rw, GetBlockHeadersMsg, &getBlockHeadersData{Origin: HashOrNumber{Hash: origin}, Amount: uint64(amount), Skip: uint64(skip), Reverse: reverse, Light: light})
}

// RequestHeadersByNumber fetches a batch of blocks' headers corresponding to the
// specified header query, based on the number of an origin block.
func (p *peer) RequestHeadersByNumber(origin uint64, amount int, skip int, reverse, light bool) error {
	logging.Debug("Fetching batch of headers", "count", amount, "fromnum", origin, "skip", skip, "reverse", reverse, "light", light)
	return p2p.Send(p.rw, GetBlockHeadersMsg, &getBlockHeadersData{Origin: HashOrNumber{Number: origin}, Amount: uint64(amount), Skip: uint64(skip), Reverse: reverse, Light: light})
}

// SendBlockHeaders sends a batch of block headers to the remote peer.
func (p *peer) SendBlockHeaders(headers []*types.Header) error {
	return p2p.Send(p.rw, BlockHeadersMsg, headers)
}

var (
	errClosed            = errors.New("peer set is closed")
	errAlreadyRegistered = errors.New("peer is already registered")
	errNotRegistered     = errors.New("peer is not registered")

	metricsPeerCount = int32(0)
)

// peerSet represents the collection of active peers currently participating in
// the Ethereum sub-protocol.
type PeerSet struct {
	peers  map[string]*peer
	lock   sync.RWMutex
	closed bool
}

// newPeerSet creates a new peer set to track the active participants.
func newPeerSet() *PeerSet {
	return &PeerSet{
		peers: make(map[string]*peer),
	}
}

// Register injects a new peer into the working set, or returns an error if the
// peer is already known. If a new peer it registered, its broadcast loop is also
// started.
func (ps *PeerSet) Register(p *peer) error {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	if ps.closed {
		return errClosed
	}
	if _, ok := ps.peers[p.id]; ok {
		return errAlreadyRegistered
	}
	ps.peers[p.id] = p

	logging.Info("peer register, id:", "count:", atomic.AddInt32(&metricsPeerCount, 1))

	go p.broadcast()

	return nil
}

// Unregister removes a remote peer from the active set, disabling any further
// actions to/from that particular entity.
func (ps *PeerSet) Unregister(id string) error {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	p, ok := ps.peers[id]
	if !ok {
		return errNotRegistered
	}
	delete(ps.peers, id)
	p.close()

	logging.Info("peer unregister", "pid", id, "count:", atomic.AddInt32(&metricsPeerCount, -1))
	return nil
}

// Peer retrieves the registered peer with the given id.
func (ps *PeerSet) Peer(id string) *peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return ps.peers[id]
}

// Len returns if the current number of peers in the set.
func (ps *PeerSet) Len() int {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return len(ps.peers)
}

// PeersWithoutBlock retrieves a list of peers that do not have a given block in
// their set of known hashes.
func (ps *PeerSet) PeersWithoutBlock(hash common.Hash) []*peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		if !p.knownBlocks.Contains(hash) {
			list = append(list, p)
		}
	}
	return list
}

// PeersWithoutTx retrieves a list of peers that do not have a given transaction
// in their set of known hashes.
// Only returns those peers whose node type is ArchiveNode or FullNode.
func (ps *PeerSet) PeersWithoutTx(hash common.Hash) []*peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		pnt := p.Node().Nodetype()
		if (pnt == params.ArchiveNode || pnt == params.FullNode) &&
			!p.knownTxs.Contains(hash) {
			list = append(list, p)
		}
	}
	return list
}

// BestPeer retrieves the known peer with the currently highest total number.
func (ps *PeerSet) BestPeer() *peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	var (
		bestPeer   *peer
		bestNumber *big.Int
		bestOrigin *big.Int
	)

	for _, p := range ps.peers {
		if _, number := p.Head(); number != nil {
			origin := p.Origin()
			if bestPeer == nil {
				bestPeer, bestNumber, bestOrigin = p, number, origin
			} else {
				switch number.Cmp(bestNumber) {
				case 0:
					if origin.Cmp(bestOrigin) < 0 {
						bestPeer, bestNumber, bestOrigin = p, number, origin
					}
				case 1:
					bestPeer, bestNumber, bestOrigin = p, number, origin
				}
			}
		}
	}

	if bestPeer == nil {
		logging.Debug(" best peer nil")
	}
	return bestPeer
}

// Close disconnects all peers.
// No new peers can be registered after Close has returned.
func (ps *PeerSet) Close() {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	for _, p := range ps.peers {
		p.Disconnect(p2p.DiscQuitting)
	}
	ps.closed = true
}
