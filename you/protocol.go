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
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/p2p"
	"math/big"
)

// Constants to match up protocol versions and messages
const (
	you8 = 8
)

// ProtocolName is the official short name of the protocol used during capability negotiation.
var ProtocolName = "you"

// ProtocolVersions are the supported versions of the you protocol (first is primary).
var ProtocolVersions = []uint{you8}

// ProtocolLengths are the number of implemented message corresponding to different protocol versions.
var ProtocolLengths = []uint64{18}

const ProtocolMaxMsgSize = 10 * 1024 * 1024 // Maximum cap on the size of a protocol message

// Code must not exceeds the ProtocolLengths
const (
	StatusMsg          = 0x00
	NewBlockMsg        = 0x01
	NewBlockHashMsg    = 0x02
	TxMsg              = 0x03
	GetBlockMsg        = 0x04
	ConsensusCtrMsg    = 0x05
	ConsensusMsg       = 0x06
	GetBlockHeadersMsg = 0x07 // get batch of headers
	BlockHeadersMsg    = 0x08
	GetNodeDataMsg     = 0x09 // get trie node data
	NodeDataMsg        = 0x0A
	GetBlockBodiesMsg  = 0x0B // get batch of bodies
	BlockBodiesMsg     = 0x0C
	GetReceiptsMsg     = 0x0D // get batch of receipts
	ReceiptsMsg        = 0x0E
)

type errCode int

const (
	ErrMsgTooLarge = iota
	ErrDecode
	ErrInvalidMsgCode
	ErrProtocolVersionMismatch
	ErrNetworkIdMismatch
	ErrGenesisBlockMismatch
	ErrNoStatusMsg
	ErrExtraStatusMsg
	ErrSuspendedPeer
)

//@wei 暂时先通过init预制广播消息进行过滤 todo
func init() {
	p2p.RegisterFilterCode(NewBlockMsg)
	p2p.RegisterFilterCode(NewBlockHashMsg)
	p2p.RegisterFilterCode(TxMsg)
	p2p.RegisterFilterCode(GetBlockMsg)
	p2p.RegisterFilterCode(ConsensusCtrMsg)
	p2p.RegisterFilterCode(ConsensusMsg)
}

func (e errCode) String() string {
	return errorToString[int(e)]
}

// XXX change once legacy code is out
var errorToString = map[int]string{
	ErrMsgTooLarge:             "Message too long",
	ErrDecode:                  "Invalid message",
	ErrInvalidMsgCode:          "Invalid message code",
	ErrProtocolVersionMismatch: "Protocol version mismatch",
	ErrNetworkIdMismatch:       "NetworkId mismatch",
	ErrGenesisBlockMismatch:    "Genesis block mismatch",
	ErrNoStatusMsg:             "No status message",
	ErrExtraStatusMsg:          "Extra status message",
	ErrSuspendedPeer:           "Suspended peer",
}

type txPool interface {
	// AddRemotes should add the given transactions to the pool.
	AddRemotes(types.Transactions) []error

	// Pending should return pending transactions.
	// The slice should be modifiable by the caller.
	Pending() (map[common.Address]types.Transactions, error)

	// SubscribeNewTxsEvent should return an event subscription of
	// NewTxsEvent and send events to the given channel.
	SubscribeNewTxsEvent(chan<- core.NewTxsEvent) event.Subscription
}

// statusData is the network packet for the status message.
type statusData struct {
	ProtocolVersion uint32
	NetworkId       uint64
	Origin          uint64 //chain origin height
	Height          uint64 //latest height
	CurrentBlock    common.Hash
	GenesisBlock    common.Hash
}

// NewBlockHashesData is the network packet for the block announcements.
type NewBlockHashesData []struct {
	Hash   common.Hash // Hash of one particular block being announced
	Number uint64      // Number of one particular block being announced
}

// HashOrNumber is a combined field for specifying an origin block.
type HashOrNumber struct {
	Hash   common.Hash // Block hash from which to retrieve headers (excludes Number)
	Number uint64      // Block hash from which to retrieve headers (excludes Hash)
}

type BlocksData []struct {
	Block  *types.Block
	Number *big.Int
}

// getBlockHeadersData represents a block header query.
type getBlockHeadersData struct {
	Origin  HashOrNumber // Block from which to retrieve headers
	Amount  uint64       // Maximum number of headers to retrieve
	Skip    uint64       // Blocks to skip between consecutive headers
	Reverse bool         // Query direction (false = rising towards latest, true = falling towards genesis)
	Light   bool         // If true, the returned headers should not contain the Validator field. Use for a light store.
}

type GetNodeDataMsgData struct {
	Kind   types.TrieKind
	Hashes []common.Hash
}
