// Copyright 2014 The go-ethereum Authors
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

// Package types contains data types related to Ethereum consensus.
package types

import (
	"fmt"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/crypto/sha3"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"io"
	"math/big"
	"reflect"
	"sort"
	"sync/atomic"
	"time"
)

var (
	EmptyRootHash = DeriveSha(Transactions{})
)

//go:generate gencodec -type Header -field-override headerMarshaling -out gen_header_json.go

// Header represents a block header in the YOUChain blockchain.
type Header struct {
	ParentHash     common.Hash       `json:"parentHash"       gencodec:"required"`
	Coinbase       common.Address    `json:"miner"            gencodec:"required"`
	Root           common.Hash       `json:"stateRoot"        gencodec:"required"`
	ValRoot        common.Hash       `json:"valRoot"          gencodec:"required"`
	StakingRoot    common.Hash       `json:"stakingRoot"      gencodec:"required"`
	TxHash         common.Hash       `json:"transactionsRoot" gencodec:"required"`
	ReceiptHash    common.Hash       `json:"receiptsRoot"     gencodec:"required"`
	Bloom          Bloom             `json:"logsBloom"        gencodec:"required"`
	Number         *big.Int          `json:"number"           gencodec:"required"`
	Subsidy        *big.Int          `json:"subsidy"          gencodec:"required"`
	GasRewards     *big.Int          `json:"gasRewards"       gencodec:"required"`
	GasLimit       uint64            `json:"gasLimit"         gencodec:"required"`
	GasUsed        uint64            `json:"gasUsed"          gencodec:"required"`
	Time           uint64            `json:"timestamp"        gencodec:"required"`
	CurrVersion    params.YouVersion `json:"version"          gencodec:"required"`
	NextVersion    params.YouVersion `json:"nextVersion"      gencodec:"required"`
	NextApprovals  uint64            `json:"nextApprovals"    gencodec:"required"` //vote count for next version
	NextVoteBefore uint64            `json:"nextVoteBefore"   gencodec:"required"` //vote until specific round
	NextSwitchOn   uint64            `json:"nextSwitchOn"     gencodec:"required"` //if voting passes threshold, switch version at specific round
	MixDigest      common.Hash       `json:"mixHash"          gencodec:"required"`
	Extra          []byte            `json:"extraData"        gencodec:"required"`
	SlashData      []byte            `json:"slashData"        gencodec:"required"`
	Consensus      []byte            `json:"consensus"        gencodec:"required"`
	ChtRoot        []byte            `json:"chtRoot"          gencodec:"required"`   //CHT Root in bytes, only appears at the i*params.ACoCHTFrequency blocks
	BltRoot        []byte            `json:"bltRoot"          gencodec:"required"`   //Bloombits trie Root in bytes, appears with cht root
	Validator      []byte            `json:"validator"        gencodec:"required"`   //hash omit
	Signature      []byte            `json:"signature"        gencodec:"required"`   //hash omit, sig(hash(header,!Validator,!Signature))
	Certificate    []byte            `json:"certificate"        gencodec:"required"` //hash omit
}

// field type overrides for gencodec
type headerMarshaling struct {
	Number         *hexutil.Big
	GasLimit       hexutil.Uint64
	GasUsed        hexutil.Uint64
	GasRewards     *hexutil.Big
	Subsidy        *hexutil.Big
	Time           hexutil.Uint64
	CurrVersion    hexutil.Uint64
	NextVersion    hexutil.Uint64
	NextApprovals  hexutil.Uint64
	NextVoteBefore hexutil.Uint64
	NextSwitchOn   hexutil.Uint64
	Extra          hexutil.Bytes
	SlashData      hexutil.Bytes
	Consensus      hexutil.Bytes
	ChtRoot        hexutil.Bytes
	BltRoot        hexutil.Bytes
	Validator      hexutil.Bytes
	Signature      hexutil.Bytes
	Certificate    hexutil.Bytes
	Hash           common.Hash `json:"hash"` // adds call to Hash() in MarshalJSON
}

// UpgradeVote represents the vote of the block proposer with
// respect to protocol upgrades.
type UpgradeVote struct {
	// ProposedVersion indicates a proposed upgrade
	ProposedVersion params.YouVersion

	// WaitRounds indicates the time between acceptance and execution
	WaitRounds uint64

	// UpgradeApprove indicates a yes vote for the current proposal
	UpgradeApprove bool
}

// Hash returns the block hash of the header, which is simply the keccak256 hash of its
// RLP encoding.
func (h *Header) Hash() common.Hash {
	// If the mix digest is equivalent to the predefined digest, use
	// specific hash calculation.
	if h.MixDigest == UConMixHash {
		if uconHeader := UconFilteredHeader(h); uconHeader != nil {
			return rlpHash(uconHeader)
		}
	}
	return rlpHash(h)
}

var headerSize = common.StorageSize(reflect.TypeOf(Header{}).Size())

// Size returns the approximate memory used by all internal contents. It is used
// to approximate and limit the memory consumption of various caches.
func (h *Header) Size() common.StorageSize {
	total := len(h.Extra) + len(h.SlashData) + len(h.Consensus) + len(h.ChtRoot) + len(h.BltRoot) + len(h.Validator) + len(h.Signature) + len(h.Certificate) +
		(h.GasRewards.BitLen()+h.Subsidy.BitLen()+h.Number.BitLen())/8
	return headerSize + common.StorageSize(total)
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

func (h *Header) VersionStateString() string {
	if h == nil {
		return ""
	}
	return fmt.Sprintf("{ version:%d, nextVersion:%d, nextApprovals:%d, nextVoteBefore:%d, nextSwitchOn:%d }", h.CurrVersion, h.NextVersion, h.NextApprovals, h.NextVoteBefore, h.NextSwitchOn)
}

// Body is a simple (mutable, non-safe) data container for storing and moving
// a block's data contents (transactions and uncles) together.
type Body struct {
	Transactions []*Transaction
}

// Block represents an entire block in the Ethereum blockchain.
type Block struct {
	header       *Header
	transactions Transactions

	// caches
	hash atomic.Value
	size atomic.Value

	// These fields are used by package eth to track
	// inter-peer block relay.
	ReceivedAt   time.Time
	ReceivedFrom interface{}
}

func (b *Block) String() string {
	str := fmt.Sprintf(`Block(#%v): Size: %v {header: %v Transactions: %v }`, b.Number(), b.Size(), b.header, b.transactions)
	return str
}

// "external" block encoding. used for eth protocol, etc.
type extblock struct {
	Header *Header
	Txs    []*Transaction
}

// NewBlock creates a new block. The input data is copied,
// changes to header and to the field values will not affect the
// block.
//
// The values of TxHash, UncleHash, ReceiptHash and Bloom in header
// are ignored and set to values derived from the given txs, uncles
// and receipts.
func NewBlock(header *Header, txs []*Transaction, receipts []*Receipt) *Block {
	b := &Block{header: CopyHeader(header)}

	if len(txs) == 0 {
		b.header.TxHash = EmptyRootHash
	} else {
		b.header.TxHash = DeriveSha(Transactions(txs))
		b.transactions = make(Transactions, len(txs))
		copy(b.transactions, txs)
	}

	if len(receipts) == 0 {
		b.header.ReceiptHash = EmptyRootHash
	} else {
		b.header.ReceiptHash = DeriveSha(Receipts(receipts))
		b.header.Bloom = CreateBloom(receipts)
	}

	return b
}

// NewBlockWithHeader creates a block with the given header data. The
// header data is copied, changes to header and to the field values
// will not affect the block.
func NewBlockWithHeader(header *Header) *Block {
	return &Block{header: CopyHeader(header)}
}

// CopyHeader creates a deep copy of a block header to prevent side effects from
// modifying a header variable.
func CopyHeader(h *Header) *Header {
	cpy := *h
	if cpy.Number = new(big.Int); h.Number != nil {
		cpy.Number.Set(h.Number)
	}
	if cpy.GasRewards = new(big.Int); h.GasRewards != nil {
		cpy.GasRewards.Set(h.GasRewards)
	}
	if cpy.Subsidy = new(big.Int); h.Subsidy != nil {
		cpy.Subsidy.Set(h.Subsidy)
	}
	if len(h.Extra) > 0 {
		cpy.Extra = make([]byte, len(h.Extra))
		copy(cpy.Extra, h.Extra)
	}
	if len(h.SlashData) > 0 {
		cpy.SlashData = make([]byte, len(h.SlashData))
		copy(cpy.SlashData, h.SlashData)
	}
	if len(h.ChtRoot) > 0 {
		cpy.ChtRoot = make([]byte, len(h.ChtRoot))
		copy(cpy.ChtRoot, h.ChtRoot)
	}
	if len(h.BltRoot) > 0 {
		cpy.BltRoot = make([]byte, len(h.BltRoot))
		copy(cpy.BltRoot, h.BltRoot)
	}
	if len(h.Consensus) > 0 {
		cpy.Consensus = make([]byte, len(h.Consensus))
		copy(cpy.Consensus, h.Consensus)
	}
	if len(h.Validator) > 0 {
		cpy.Validator = make([]byte, len(h.Validator))
		copy(cpy.Validator, h.Validator)
	}
	if len(h.Signature) > 0 {
		cpy.Signature = make([]byte, len(h.Signature))
		copy(cpy.Signature, h.Signature)
	}
	if len(h.Certificate) > 0 {
		cpy.Certificate = make([]byte, len(h.Certificate))
		copy(cpy.Certificate, h.Certificate)
	}

	return &cpy
}

// DecodeRLP decodes the Ethereum
func (b *Block) DecodeRLP(s *rlp.Stream) error {
	var eb extblock
	_, size, _ := s.Kind()
	if err := s.Decode(&eb); err != nil {
		return err
	}
	b.header, b.transactions = eb.Header, eb.Txs
	b.size.Store(common.StorageSize(rlp.ListSize(size)))
	return nil
}

// EncodeRLP serializes b into the Ethereum RLP block format.
func (b *Block) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, extblock{
		Header: b.header,
		Txs:    b.transactions,
	})
}

func (b *Block) Transactions() Transactions { return b.transactions }

func (b *Block) Transaction(hash common.Hash) *Transaction {
	for _, transaction := range b.transactions {
		if transaction.Hash() == hash {
			return transaction
		}
	}
	return nil
}

func (b *Block) Number() *big.Int     { return new(big.Int).Set(b.header.Number) }
func (b *Block) GasLimit() uint64     { return b.header.GasLimit }
func (b *Block) GasUsed() uint64      { return b.header.GasUsed }
func (b *Block) GasRewards() *big.Int { return b.header.GasRewards }
func (b *Block) Subsidy() *big.Int    { return b.header.Subsidy }
func (b *Block) Time() uint64         { return b.header.Time }

func (b *Block) NumberU64() uint64        { return b.header.Number.Uint64() }
func (b *Block) MixDigest() common.Hash   { return b.header.MixDigest }
func (b *Block) Bloom() Bloom             { return b.header.Bloom }
func (b *Block) Coinbase() common.Address { return b.header.Coinbase }
func (b *Block) Root() common.Hash        { return b.header.Root }
func (b *Block) ParentHash() common.Hash  { return b.header.ParentHash }
func (b *Block) TxHash() common.Hash      { return b.header.TxHash }
func (b *Block) ValRoot() common.Hash     { return b.header.ValRoot }
func (b *Block) StakingRoot() common.Hash { return b.header.StakingRoot }
func (b *Block) ReceiptHash() common.Hash { return b.header.ReceiptHash }
func (b *Block) Extra() []byte            { return common.CopyBytes(b.header.Extra) }
func (b *Block) Validator() []byte        { return b.header.Validator }
func (b *Block) Consensus() []byte        { return b.header.Consensus }
func (b *Block) Signature() []byte        { return b.header.Signature }
func (b *Block) Certificate() []byte      { return b.header.Certificate }

func (b *Block) CurrVersion() params.YouVersion { return b.header.CurrVersion }

func (b *Block) Header() *Header { return CopyHeader(b.header) }

// Body returns the non-header content of the block.
func (b *Block) Body() *Body { return &Body{b.transactions} }

// Size returns the true RLP encoded storage size of the block, either by encoding
// and returning it, or returning a previsouly cached value.
func (b *Block) Size() common.StorageSize {
	if size := b.size.Load(); size != nil {
		return size.(common.StorageSize)
	}
	c := writeCounter(0)
	rlp.Encode(&c, b)
	b.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}

type writeCounter common.StorageSize

func (c *writeCounter) Write(b []byte) (int, error) {
	*c += writeCounter(len(b))
	return len(b), nil
}

// WithSeal returns a new block with the data from b but the header replaced with
// the sealed one.
func (b *Block) WithSeal(header *Header) *Block {
	cpy := CopyHeader(header)

	return &Block{
		header:       cpy,
		transactions: b.transactions,
	}
}

// WithBody returns a new block with the given transactions.
func (b *Block) WithBody(body *Body) *Block {
	block := &Block{
		header:       CopyHeader(b.header),
		transactions: make([]*Transaction, len(body.Transactions)),
	}
	copy(block.transactions, body.Transactions)
	return block
}

// Hash returns the keccak256 hash of b's header.
// The hash is computed on the first call and cached thereafter.
func (b *Block) Hash() common.Hash {
	if hash := b.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := b.header.Hash()
	b.hash.Store(v)
	return v
}

type Blocks []*Block

type BlockBy func(b1, b2 *Block) bool

func (self BlockBy) Sort(blocks Blocks) {
	bs := blockSorter{
		blocks: blocks,
		by:     self,
	}
	sort.Sort(bs)
}

type blockSorter struct {
	blocks Blocks
	by     func(b1, b2 *Block) bool
}

func (self blockSorter) Len() int { return len(self.blocks) }
func (self blockSorter) Swap(i, j int) {
	self.blocks[i], self.blocks[j] = self.blocks[j], self.blocks[i]
}
func (self blockSorter) Less(i, j int) bool { return self.by(self.blocks[i], self.blocks[j]) }

func Number(b1, b2 *Block) bool { return b1.header.Number.Cmp(b2.header.Number) < 0 }
