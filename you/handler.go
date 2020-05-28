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
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/p2p"
	"github.com/youchainhq/go-youchain/p2p/enode"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/you/downloader"
	"github.com/youchainhq/go-youchain/you/fetcher"
	"github.com/youchainhq/go-youchain/youdb"
	"math"
	"math/big"
	"sync"
	"time"
)

const (
	softResponseLimit = 2 * 1024 * 1024 // Target maximum size of returned blocks, headers or node data.
	// minimim number of peers to broadcast new blocks to
	minBroadcastPeers = 4
)

type syncAction int

type peerLifecycle byte

const (
	peerAdded peerLifecycle = iota
	peerRemoved
)

const (
	syncActionNewBlock syncAction = iota
	syncActionNewPeer
	syncActionForceSync
)

//for fallback usage
type GenericProtocolManager interface {
	consensus.MineInserter
	Start(p2pserver interface{}, maxPeers int)
	Stop()
	GetSubProtocols() []p2p.Protocol
	Downloader() *downloader.Downloader
}

type defaultMsgFun func(p *peer, msg p2p.Msg)

type peerLifecycleFun func(p *peer, flag peerLifecycle)

func errResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}

type ProtocolManager struct {
	downloaderSyncing uint32
	syncMode          downloader.SyncMode

	networkID uint64

	SubProtocols []p2p.Protocol

	eventMux *event.TypeMux
	//acceptTxs uint32 // Flag whether we're considered synchronised (enables transaction processing)
	txpool   txPool
	txsCh    chan core.NewTxsEvent
	txsSub   event.Subscription
	txsyncCh chan *txsync

	blockchain       *core.BlockChain
	newMinedBlockCh  chan core.NewMinedBlockEvent
	newMinedBlockSub event.Subscription

	maxPeers  int
	p2pserver *p2p.Server
	peers     *PeerSet
	// channels for fetcher, syncer, txsyncLoop
	newPeerCh   chan *peer
	noMorePeers chan struct{}

	fetcher    *fetcher.Fetcher
	downloader *downloader.Downloader

	quitSync chan struct{}

	defaultMsgFun    defaultMsgFun
	peerLifecycleFun peerLifecycleFun

	// wait group is used for graceful shutdowns during downloading
	// and processing
	wg sync.WaitGroup
}

func (pm *ProtocolManager) Downloader() *downloader.Downloader {
	return pm.downloader
}

// NewProtocolManager returns a new Ethereum sub protocol manager. The Ethereum sub protocol manages peers capable
// with the Ethereum network.
func NewProtocolManager(txpool txPool, blockchain *core.BlockChain, engine consensus.Engine,
	mux *event.TypeMux, chaindb youdb.Database, mode downloader.SyncMode) (*ProtocolManager, error) {
	// Create the protocol manager with the base fields
	manager := &ProtocolManager{
		downloaderSyncing: 0,

		networkID:   params.NetworkId(),
		eventMux:    mux,
		txpool:      txpool,
		blockchain:  blockchain,
		peers:       newPeerSet(),
		newPeerCh:   make(chan *peer),
		noMorePeers: make(chan struct{}),
		txsyncCh:    make(chan *txsync),
		quitSync:    make(chan struct{}),
	}

	manager.syncMode = mode

	// 需要共识层进行验证
	validator := func(header *types.Header) error {
		return engine.VerifyHeader(blockchain, header, true)
	}
	heighter := func() uint64 {
		logging.Debug("heighter get current block number:", "current number", blockchain.CurrentBlock().NumberU64())
		return blockchain.CurrentBlock().NumberU64()
	}
	inserter := func(blocks types.Blocks) error {
		//atomic.StoreUint32(&manager.acceptTxs, 1) // Mark initial sync done on any fetcher import
		for i, blk := range blocks {
			logging.Info("fetcher inserter insertchain", "height", blk.NumberU64(), "hash", blk.Hash().String(), "txs", blk.Transactions().Len(), "i", i, "total", len(blocks))
		}

		return manager.blockchain.InsertChain(blocks)
	}

	manager.SubProtocols = make([]p2p.Protocol, 0, len(ProtocolVersions))
	for i, version := range ProtocolVersions {
		manager.SubProtocols = append(manager.SubProtocols, p2p.Protocol{
			Name:    ProtocolName,
			Version: version,
			Length:  ProtocolLengths[i],
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
				peer := manager.newPeer(int(version), p, rw)
				select {
				case <-manager.quitSync:
					return p2p.DiscQuitting
				default:
					manager.wg.Add(1)
					defer manager.wg.Done()
					return manager.handle(peer, func() {
						select {
						case manager.newPeerCh <- peer:
							logging.Info("newPeerCh<-", "pid", peer.id)
						default:
							logging.Info("newPeerCh is busy", "pid", peer.id)
						}
					})
				}
			},
			NodeInfo: func() interface{} {
				return manager.NodeInfo()
			},
			PeerInfo: func(id enode.ID) interface{} {
				if p := manager.peers.Peer(fmt.Sprintf("%x", id[:8])); p != nil {
					return p.Info()
				}
				return nil
			},
		})
	}

	manager.downloader = downloader.New(blockchain, nil, chaindb, manager.removePeer, mux)
	//set blockchain state fetcher
	blockchain.SetVldFetcher(manager.downloader)

	manager.fetcher = fetcher.New(blockchain.GetBlockByHash, validator, manager.BroadcastBlock, heighter, inserter, manager.removePeer)

	return manager, nil
}

func (pm *ProtocolManager) newPeer(pv int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	return newPeer(pv, p, rw)
}

// handle is the callback invoked to manage the life cycle of an eth peer. When
// this function terminates, the peer is disconnected.
func (pm *ProtocolManager) handle(p *peer, hook func()) error {
	// Ignore maxPeers if this is a trusted peer
	if pm.peers.Len() >= pm.maxPeers && !p.Peer.Info().Network.Trusted {
		logging.Error("handle error for too many peers", "pid", p.id)
		return p2p.DiscTooManyPeers
	}
	p.Log().Debug("peer connected", "name", p.Name())

	// Execute the Ethereum handshake
	var (
		genesis = pm.blockchain.Genesis()
		head    = pm.blockchain.CurrentHeader()
		origin  = pm.blockchain.FullOriginBlockNumber().Uint64()
		number  = head.Number.Uint64()
		hash    = head.Hash()
	)
	if err := p.Handshake(pm.networkID, number, hash, origin, genesis.Hash()); err != nil {
		logging.Debug("handler handshake failed", "err", err)
		return err
	}
	// Register the peer locally
	if err := pm.peers.Register(p); err != nil {
		logging.Error("handler peer registration failed", "err", err)
		return err
	}
	pnt := p.Node().Nodetype()
	if pnt == params.ArchiveNode || pnt == params.FullNode {
		if err := pm.downloader.RegisterPeer(p.id, p); err != nil {
			logging.Error("handler downloader peer registration failed", "err", err)
			return err
		}
	}

	//todo metrics
	defer pm.removePeer(p.id)

	if pm.peerLifecycleFun != nil {
		pm.peerLifecycleFun(p, peerAdded)
	}

	if pnt == params.ArchiveNode || pnt == params.FullNode {
		// Propagate existing transactions. new transactions appearing
		// after this will be sent via broadcasts.
		pm.syncTransactions(p)
	}

	logging.Info("handshake accept new peer", "pid", p.id, "total", pm.peers.Len())

	if hook != nil {
		hook()
	}

	// Handle incoming messages until the connection is torn down
	for {
		if err := pm.handleMsg(p); err != nil {
			logging.Info("handleMsg from broke", "pid", p.id, "err", err)
			return err
		}
	}
}

// handleMsg is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
func (pm *ProtocolManager) handleMsg(p *peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	start := time.Now()
	defer func() { p2p.PublicPMHandleMsgUsingTime(start) }()
	var (
		msg p2p.Msg
		err error
	)
	msg, err = p.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Size > ProtocolMaxMsgSize {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	}
	defer msg.Discard()

	packets, traffic := nilInPacketsMeter, nilInTrafficMeter
	switch {
	case msg.Code == StatusMsg:
		// Status messages should never arrive after the handshake
		return errResp(ErrExtraStatusMsg, "uncontrolled status message")
	case msg.Code == NewBlockMsg:
		err = pm.handleNewBlockMsg(p, msg)
		packets, traffic = propBlockInPacketsMeter, propBlockInTrafficMeter
	case msg.Code == NewBlockHashMsg:
		err = pm.handleNewBlockHashMsg(p, msg)
		packets, traffic = propBlockHashInPacketsMeter, propBlockHashInTrafficMeter
	case msg.Code == TxMsg:
		err = pm.handleNewTxMsg(p, msg)
		packets, traffic = propTxnInPacketsMeter, propTxnInTrafficMeter
	case msg.Code == GetBlockMsg:
		err = pm.handleGetBlockMsg(p, msg)
	case msg.Code == GetBlockHeadersMsg:
		err = pm.handleGetHeadersMsg(p, msg)
	case msg.Code == BlockHeadersMsg:
		err = pm.handleReceiveHeadersMsg(p, msg)
		packets, traffic = propHeaderInPacketsMeter, propHeaderInTrafficMeter
	case msg.Code == GetNodeDataMsg:
		err = pm.handleGetNodeDataMsg(p, msg)
	case msg.Code == NodeDataMsg:
		err = pm.handleNodeDataMsg(p, msg)
	case msg.Code == GetBlockBodiesMsg:
		err = pm.handleGetBlockBodiesMsg(p, msg)
	case msg.Code == BlockBodiesMsg:
		err = pm.handleBlockBodiesMsg(p, msg)
	case msg.Code == GetReceiptsMsg:
		err = pm.handleGetReceiptsMsg(p, msg)
	case msg.Code == ReceiptsMsg:
		err = pm.handleReceiptsMsg(p, msg)
	default:
		if pm.defaultMsgFun != nil {
			pm.defaultMsgFun(p, msg)
		}
	}
	if packets != nil {
		packets.Mark(1)
		traffic.Mark(int64(msg.Size))
	}
	if err != nil {
		logging.Error("handleMsg error", "code", msg.Code, "err", err)
	}
	return nil
}

func (pm *ProtocolManager) handleNewTxMsg(p *peer, msg p2p.Msg) error {
	// Transactions can be processed, parse all of them and deliver to the pool
	var txs []*types.Transaction
	if err := msg.Decode(&txs); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	for i, tx := range txs {
		// Validate and mark the remote transaction
		if tx == nil {
			return errResp(ErrDecode, "transaction %d is nil", i)
		}
		p.MarkTransaction(tx.Hash())
	}

	logging.Debug("receive txs from", "pid", p.id, "txs", len(txs))
	pm.txpool.AddRemotes(txs)

	return nil
}

func (pm *ProtocolManager) handleNewBlockMsg(p *peer, msg p2p.Msg) error {
	// Retrieve and decode the propagated block
	//var request newBlockData
	var block types.Block
	if err := msg.Decode(&block); err != nil {
		logging.Error("Decode from bytes failed. ", err)
		return fmt.Errorf("%v: %v", msg, err)
	}
	logging.Info("New block data: ", "number", block.NumberU64(), "hash", block.Hash().String(), "current number", pm.blockchain.CurrentBlock().NumberU64())

	block.ReceivedAt = time.Now()
	block.ReceivedFrom = p

	// Mark the peer as owning the block and schedule it for import
	p.MarkBlock(block.Hash())
	_ = pm.fetcher.Enqueue(p.id, &block)

	var (
		trueHead   = block.ParentHash() //use parentHash, number, to make sure block is exist
		trueNumber = big.NewInt(block.Number().Int64() - 1)
	)
	// Update the peers if better than the previous
	if _, number := p.Head(); number == nil || trueNumber.Cmp(number) > 0 {
		p.SetHead(trueHead, trueNumber)

		currentBlock := pm.blockchain.CurrentBlock()
		// p's parent block number is greater than local block number
		// cautious! downloader should only handle the far behind situation.
		if trueNumber.Cmp(currentBlock.Number()) > 0 {
			go pm.synchronise(p, syncActionNewBlock)
		}
	}

	return nil
}

func (pm *ProtocolManager) handleNewBlockHashMsg(p *peer, msg p2p.Msg) error {
	var announces NewBlockHashesData
	if err := msg.Decode(&announces); err != nil {
		return fmt.Errorf("msg %v: %v", msg, err)
	}

	// Mark the hashes as present at the remote node
	for _, block := range announces {
		p.MarkBlock(block.Hash)
	}
	// Schedule all the unknown hashes for retrieval
	unknown := make(NewBlockHashesData, 0, len(announces))
	for _, block := range announces {
		logging.Debug("New block", "number", block.Number, "hash", block.Hash.String(), "current height", pm.blockchain.CurrentBlock().NumberU64())
		if !pm.blockchain.HasBlock(block.Hash, block.Number) {
			unknown = append(unknown, block)
		}
	}
	for _, block := range unknown {
		if err := pm.fetcher.Notify(p.id, block.Hash, block.Number, time.Now(), p.RequestGetBlock); err != nil {
			logging.Error("fetcher.Notify", "err", err)
		}
	}

	return nil
}

// handleGetHeadersMsg send headers from number(include number)
func (pm *ProtocolManager) handleGetHeadersMsg(p *peer, msg p2p.Msg) error {
	logging.Trace("pm message handle GetHeadersMsg", "from pid", p.id)
	var query getBlockHeadersData
	if err := msg.Decode(&query); err != nil {
		return errResp(ErrDecode, "%v: %v", msg, err)
	}
	hashMode := query.Origin.Hash != (common.Hash{})

	// for log
	qOrigin := ""
	if hashMode {
		qOrigin = query.Origin.Hash.String()
	} else {
		qOrigin = hexutil.EncodeUint64(query.Origin.Number)
	}
	logging.Info("handleGetHeadersMsg", "pid", p.id, "origin", qOrigin, "amount", query.Amount, "skip", query.Skip, "reverse", query.Reverse, "light", query.Light)

	var (
		headers         []*types.Header
		unknown         bool
		maxNonCanonical = uint64(100)
		first           = true
	)

	for !unknown && len(headers) < int(query.Amount) && len(headers) < downloader.MaxHeaderFetch {
		var origin *types.Header

		if hashMode {
			if first {
				first = false
				origin = pm.blockchain.GetHeaderByHash(query.Origin.Hash)
				if origin != nil {
					query.Origin.Number = origin.Number.Uint64()
				}
			} else {
				origin = pm.blockchain.GetHeader(query.Origin.Hash, query.Origin.Number)
			}
		} else {
			origin = pm.blockchain.GetHeaderByNumber(query.Origin.Number)
		}

		if origin == nil {
			break
		} else if query.Light {
			// For light query, no need to send the Validator field.
			//
			// IMPORTANT: Can NOT directly modify the header returned by blockchain,
			// because it's a reference object and it will be cached by the blockchain!
			header := types.CopyHeader(origin)
			header.Validator = []byte{}
			origin = header
		}
		headers = append(headers, origin)

		switch {
		case hashMode && query.Reverse:
			// Hash based traversal towards the genesis block
			ancestor := query.Skip + 1
			if ancestor == 0 {
				unknown = true
			} else {
				query.Origin.Hash, query.Origin.Number = pm.blockchain.GetAncestor(query.Origin.Hash, query.Origin.Number, ancestor, &maxNonCanonical)
				unknown = query.Origin.Hash == common.Hash{}
			}
		case hashMode && !query.Reverse:
			var (
				current = origin.Number.Uint64()
				next    = current + query.Skip + 1
			)
			if next <= current {
				unknown = true
			} else {
				if header := pm.blockchain.GetHeaderByNumber(next); header != nil {
					nextHash := header.Hash()
					expOldHash, _ := pm.blockchain.GetAncestor(nextHash, next, query.Skip+1, &maxNonCanonical)
					if expOldHash == query.Origin.Hash {
						query.Origin.Hash, query.Origin.Number = nextHash, next
					} else {
						unknown = true
					}
				} else {
					unknown = true
				}
			}
		case query.Reverse:
			// Number based traversal towards the genesis block
			if query.Origin.Number >= query.Skip+1 {
				query.Origin.Number -= query.Skip + 1
			} else {
				unknown = true
			}
		case !query.Reverse:
			// Number based traversal towards the leaf block
			query.Origin.Number += query.Skip + 1
		}
	}
	logging.Trace("pm message handle GetHeadersMsg result:", "len", len(headers))
	return p.SendBlockHeaders(headers)
}

func (pm *ProtocolManager) handleReceiveHeadersMsg(p *peer, msg p2p.Msg) error {
	// A batch of headers arrived to one of our previous requests
	var headers []*types.Header
	if err := msg.Decode(&headers); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}

	logging.Trace("pm message handle ReceiveHeadersMsg headers:", "count", len(headers), "from pid", p.id)
	err := pm.downloader.DeliverHeaders(p.id, headers)
	if err != nil {
		logging.Debug("Failed to deliver headers", "err", err)
	}
	return nil
}

func (pm *ProtocolManager) handleGetBlockMsg(p *peer, msg p2p.Msg) error {
	// mark peer
	var hash common.Hash
	if err := msg.Decode(&hash); err != nil {
		logging.Error("Bytes to hash failed.", err)
		return err
	}

	logging.Info("handleGetBlockMsg from ", "pid", p.id, "request block: hash", hash.String())

	if block := pm.blockchain.GetBlockByHash(hash); block != nil {
		logging.Debug("send Block to: ", "pid", p.id)
		return p.SendNewBlock(block)
	}

	return errors.New("send block failed")
}

func (pm *ProtocolManager) handleGetBlockBodiesMsg(p *peer, msg p2p.Msg) error {
	// Decode the retrieval message
	msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
	if _, err := msgStream.List(); err != nil {
		return err
	}
	// Gather blocks until the fetch or network limits is reached
	var (
		hash   common.Hash
		bytes  int
		bodies []rlp.RawValue
	)
	for bytes < softResponseLimit && len(bodies) < downloader.MaxBlockFetch {
		// Retrieve the hash of the next block
		if err := msgStream.Decode(&hash); err == rlp.EOL {
			break
		} else if err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Retrieve the requested block body, stopping if enough was found
		if data := pm.blockchain.GetBodyRLP(hash); len(data) != 0 {
			bodies = append(bodies, data)
			bytes += len(data)
		}
	}
	return p.SendBlockBodiesRLP(bodies)
}

func (pm *ProtocolManager) handleBlockBodiesMsg(p *peer, msg p2p.Msg) error {
	// A batch of block bodies arrived to one of our previous requests
	var request []*types.Body
	if err := msg.Decode(&request); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	// Deliver them all to the downloader for queuing
	transactions := make([][]*types.Transaction, len(request))

	for i, body := range request {
		transactions[i] = body.Transactions
	}
	if err := pm.downloader.DeliverBodies(p.id, transactions); err != nil {
		return err
	}
	return nil
}

func (pm *ProtocolManager) handleGetReceiptsMsg(p *peer, msg p2p.Msg) error {
	// Decode the retrieval message
	msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
	if _, err := msgStream.List(); err != nil {
		return err
	}
	// Gather state data until the fetch or network limits is reached
	var (
		hash     common.Hash
		bytes    int
		receipts []rlp.RawValue
	)
	for bytes < softResponseLimit && len(receipts) < downloader.MaxReceiptFetch {
		// Retrieve the hash of the next block
		if err := msgStream.Decode(&hash); err == rlp.EOL {
			break
		} else if err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		logging.Debug("try get receipts", "headerHash", hash.String())
		// Retrieve the requested block's receipts, skipping if unknown to us
		results := pm.blockchain.GetReceiptsByHash(hash)
		if results == nil {
			logging.Debug("can't get receipt", "headerHash", hash.String())
			if header := pm.blockchain.GetHeaderByHash(hash); header == nil || header.ReceiptHash != types.EmptyRootHash {
				continue
			}
		}
		// If known, encode and queue for response packet
		if encoded, err := rlp.EncodeToBytes(results); err != nil {
			logging.Error("Failed to encode receipt", "err", err)
		} else {
			receipts = append(receipts, encoded)
			bytes += len(encoded)
		}
	}
	return p.SendReceiptsRLP(receipts)
}

func (pm *ProtocolManager) handleReceiptsMsg(p *peer, msg p2p.Msg) error {
	// A batch of receipts arrived to one of our previous requests
	var receipts [][]*types.Receipt
	if err := msg.Decode(&receipts); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	// Deliver all to the downloader
	if err := pm.downloader.DeliverReceipts(p.id, receipts); err != nil {
		logging.Debug("Failed to deliver receipts", "err", err)
		return err
	}
	return nil
}

func (pm *ProtocolManager) handleGetNodeDataMsg(p *peer, msg p2p.Msg) error {
	var req GetNodeDataMsgData
	if err := msg.Decode(&req); err != nil {
		logging.Error("Bytes to GetNodeDataMsgData failed.", "err", err)
		return err
	}

	logging.Debug("got GetNodeData request", "fromPeer", p.id, "kind", req.Kind, "requestCount", len(req.Hashes))
	var (
		f     func(hash common.Hash) ([]byte, error)
		bytes = 0
		data  [][]byte
	)
	switch req.Kind {
	case types.KindState:
		f = pm.blockchain.StateTrieNode
	case types.KindValidator:
		f = pm.blockchain.VldTrieNode
	case types.KindCht:
		f = pm.blockchain.ChtTrieNode
	case types.KindBlt:
		f = pm.blockchain.BltTrieNode
	default:
		return fmt.Errorf("unsupported TrieKind: %d", req.Kind)
	}

	for _, hs := range req.Hashes {
		if bytes < softResponseLimit && len(data) < downloader.MaxTrieNodeFetch {
			// Retrieve the requested state entry, stopping if enough was found
			if entry, err := f(hs); err == nil {
				data = append(data, entry)
				bytes += len(entry)
			} else {
				logging.Warn("get trie node failed", "kind", req.Kind, "hash", hs.String(), "err", err)
				return err
			}
		} else {
			break
		}
	}
	logging.Debug("Responding node data", "count", len(data), "to", p.id)
	return p.SendNodeData(data)
}

func (pm *ProtocolManager) handleNodeDataMsg(p *peer, msg p2p.Msg) error {
	var data [][]byte
	if err := msg.Decode(&data); err != nil {
		logging.Error("Bytes to [][]byte failed.", err)
		return err
	}
	logging.Info("receive node data", "from pid", p.id, "len", len(data))
	if err := pm.downloader.DeliverNodeData(p.id, data); err != nil {
		logging.Error("failed to deliver trie node data", "err", err)
	}
	return nil
}

// BroadcastBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
func (pm *ProtocolManager) BroadcastBlock(block *types.Block, propagate bool) {
	hash := block.Hash()
	peers := pm.peers.PeersWithoutBlock(hash)

	logging.Info("BroadcastBlock", "height", block.Number(), "propagate", propagate, "peercount", len(peers))
	// If propagation is requested, send to a subset of the peer
	if propagate {
		// Calculate the TD of the block (it's not imported yet, so block.Td is not valid)
		//var td *big.Int
		if parent := pm.blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1); parent != nil {
		} else {
			logging.Error("Propagating dangling block", "number", block.NumberU64())
			return
		}
		// Send the block to a subset of our peers
		transferLen := int(math.Sqrt(float64(len(peers))))

		//tune
		if transferLen < minBroadcastPeers {
			transferLen = minBroadcastPeers
		}
		if transferLen > len(peers) {
			transferLen = len(peers)
		}

		transfer := peers[:transferLen]

		for _, peer := range transfer {
			peer.AsyncSendNewBlock(block)
		}
		logging.Info("Propagated block.", "number", block.NumberU64(), "recipients", len(transfer), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
		return
	}
	// if the block is indeed in out own chain, announce it
	if pm.blockchain.HasBlock(hash, block.NumberU64()) {
		logging.Info("BroadcastBlock", "height", block.Number(), "propagate", propagate, "peercount", len(peers))
		for _, peer := range peers {
			peer.AsyncSendNewBlockHash(block)
		}
		logging.Info("Announced block.", "number", block.NumberU64(), "recipients", len(peers), "duration", common.PrettyDuration(time.Since(block.ReceivedAt)))
	}
}

func (pm *ProtocolManager) blacklistAndRemovePeer(id string) {
	// Short circuit if the peer was already removed
	peer := pm.peers.Peer(id)
	if peer == nil {
		logging.Error("empty for id", "pid", id)
		return
	}
	logging.Info("blacklist And RemovePeer", "peer", peer.String())
	pm.p2pserver.AddPeerToBlacklist(peer.Peer)

	pm.removePeer(id)
}

func (pm *ProtocolManager) removePeer(id string) {
	// Short circuit if the peer was already removed
	peer := pm.peers.Peer(id)
	if peer == nil {
		logging.Error("empty for id", "pid", id)
		return
	}
	logging.Debug("Removing peer", "pid", id)

	if err := pm.peers.Unregister(id); err != nil {
		logging.Error("Peer removal failed", "peer", id, "err", err)
	}

	pnt := peer.Node().Nodetype()
	if pnt == params.ArchiveNode || pnt == params.FullNode {
		if err := pm.downloader.UnregisterPeer(id); err != nil {
			logging.Error("Peer removal failed", "peer", id, "err", err)
		}
	}

	if pm.peerLifecycleFun != nil {
		pm.peerLifecycleFun(peer, peerRemoved)
	}

	// Hard disconnect at the networking layer
	peer.Peer.Disconnect(p2p.DiscUselessPeer)
}

func (pm *ProtocolManager) Start(p2pserver interface{}, maxPeers int) {
	if p2pserver != nil {
		pm.p2pserver = p2pserver.(*p2p.Server)
	}

	pm.maxPeers = maxPeers

	//// 处理接收到的交易消息
	//go pm.handleTxMsgLoop()

	// broadcast transactions
	// 广播交易的通道。 txsCh会作为txpool的TxPreEvent订阅通道。txpool有了这种消息会通知给这个txsCh。 广播交易的goroutine会把这个消息广播出去。
	pm.txsCh = make(chan core.NewTxsEvent, txChanSize)
	pm.txsSub = pm.txpool.SubscribeNewTxsEvent(pm.txsCh)
	go pm.txBroadcastLoop()
	// txsyncLoop负责每个新连接的初始事务同步.当新的peer出现时，我们转发所有当前待处理的事务.为了最小化出口带宽使用，我们一次只发送一个小包。
	go pm.txsyncLoop()

	// broadcast mined blocks
	engine := pm.blockchain.Engine()
	switch engine.(type) {
	case consensus.Ucon:
		//do nothing
		logging.Debug("ignore newminedblock broadcast")
	default:
		pm.newMinedBlockCh = make(chan core.NewMinedBlockEvent, blockChanSize)
		pm.newMinedBlockSub = pm.blockchain.SubscribeNewMinedBlockEvent(pm.newMinedBlockCh)
		go pm.minedBroadcastLoop()
	}

	// start sync handlers
	go pm.syncer()
}

func (pm *ProtocolManager) Stop() {
	logging.Info("Stopping You protocol")

	engine := pm.blockchain.Engine()
	switch engine.(type) {
	case consensus.Ucon:
		//do nothing
	default:
		pm.txsSub.Unsubscribe()
		pm.newMinedBlockSub.Unsubscribe()
	}

	//pm.fetcher.Stop()
	//pm.downloader.Terminate()

	// Quit the sync loop.
	// After this send has completed, no new peers will be accepted.
	pm.noMorePeers <- struct{}{}

	// Quit fetcher, txsyncLoop.
	close(pm.quitSync)

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to pm.peers yet
	// will exit when they try to register.
	pm.peers.Close()

	// Wait for all peer handler goroutines and the loops to come down.
	pm.wg.Wait()

	logging.Info("You protocol stopped")
}

func (pm *ProtocolManager) GetSubProtocols() []p2p.Protocol {
	return pm.SubProtocols
}

func (pm *ProtocolManager) Insert(block *types.Block) error {
	return nil
}

// Mined broadcast loop
func (pm *ProtocolManager) minedBroadcastLoop() {
	for {
		select {
		case evt := <-pm.newMinedBlockCh:
			//log.Printf("%+v", evt.Block)
			pm.BroadcastBlock(evt.Block, true)  // First propagate block to peers
			pm.BroadcastBlock(evt.Block, false) // Only then announce to the rest

			// Err() channel will be closed when unsubscribing.
		case <-pm.newMinedBlockSub.Err():
			return
		}
	}
}

func (pm *ProtocolManager) txBroadcastLoop() {
	for {
		select {
		case evt := <-pm.txsCh:
			pm.BroadcastTxs(evt.Txs)
		case <-pm.txsSub.Err():
			return
		}
	}
}

// BroadcastTxs will propagate a batch of transactions to all peers which are not known to
// already have the given transaction.
func (pm *ProtocolManager) BroadcastTxs(txs types.Transactions) {
	var txset = make(map[*peer]types.Transactions)

	// Broadcast transactions to a batch of peers not knowing about it
	for _, tx := range txs {
		peers := pm.peers.PeersWithoutTx(tx.Hash())
		for _, peer := range peers {
			txset[peer] = append(txset[peer], tx)
		}
		//log.Info("Broadcast transaction", "all", pm.peers.Len(), "recipients", len(peers))
	}
	// FIXME include this again: peers = peers[:int(math.Sqrt(float64(len(peers))))]
	for peer, txs := range txset {
		peer.AsyncSendTransactions(txs)
	}
}

func (pm *ProtocolManager) peerCount() int {
	return pm.peers.Len()
}

// NodeInfo represents a short summary of the YOUChain sub-protocol metadata
// known about the host peer.
type NodeInfo struct {
	Network uint64      `json:"network"` // YOUChain network ID (1=MainNet, 2=PubTestNet)
	Genesis common.Hash `json:"genesis"` // SHA3 hash of the host's genesis block
	Head    common.Hash `json:"head"`    // SHA3 hash of the host's best owned block
}

// NodeInfo retrieves some protocol metadata about the running host node.
func (pm *ProtocolManager) NodeInfo() *NodeInfo {
	currentBlock := pm.blockchain.CurrentBlock()
	return &NodeInfo{
		Network: pm.networkID,
		Genesis: pm.blockchain.Genesis().Hash(),
		Head:    currentBlock.Hash(),
	}
}

func ParseNodes(input []string) []*enode.Node {
	urlArr := input
	nodes := make([]*enode.Node, 0, len(urlArr))
	for _, url := range urlArr {
		node, err := enode.ParseV4(url)
		if err != nil {
			fmt.Println("Bootstrap URL invalid", "enode", url, "err", err)
			continue
		}
		nodes = append(nodes, node)
	}

	return nodes
}
