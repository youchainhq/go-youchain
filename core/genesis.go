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

package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/common/math"
	"github.com/youchainhq/go-youchain/core/rawdb"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/youdb"
)

//go:generate gencodec -type Genesis -field-override genesisSpecMarshaling -out gen_genesis.go
//go:generate gencodec -type GenesisAccount -field-override genesisAccountMarshaling -out gen_genesis_account.go
//go:generate gencodec -type GenesisValidator -field-override genesisValidatorMarshaling -out gen_genesis_validator.go

var ErrGenesisNoNetworkId = errors.New("genesis has no networkId")

// Genesis specifies the header fields, state of a genesis block. It also defines hard
// fork switch-over blocks through the chain configuration.
type Genesis struct {
	NetworkId   uint64            `json:"networkId"`
	Timestamp   uint64            `json:"timestamp"`
	GasLimit    uint64            `json:"gasLimit"   gencodec:"required"`
	ExtraData   []byte            `json:"extraData"`
	Consensus   []byte            `json:"consensus"`
	Mixhash     common.Hash       `json:"mixHash"`
	Coinbase    common.Address    `json:"coinbase"`
	Alloc       GenesisAlloc      `json:"alloc"      gencodec:"required"`
	Validators  GenesisValidators `json:"validators"`
	CurrVersion params.YouVersion `json:"version"    gencodec:"required"`

	// These fields are used for consensus tests. Please don't use them
	// in actual genesis blocks.
	Number     uint64      `json:"number"`
	GasUsed    uint64      `json:"gasUsed"`
	ParentHash common.Hash `json:"parentHash"`
}

type GenesisValidator struct {
	Name            string               `json:"name"`
	OperatorAddress common.Address       `json:"operatorAddress"`
	Coinbase        common.Address       `json:"coinbase"`
	MainPubKey      hexutil.Bytes        `json:"mainPubKey"`
	BlsPubKey       hexutil.Bytes        `json:"blsPubKey"`
	Token           *big.Int             `json:"token"`
	Role            params.ValidatorRole `json:"role"`
	Status          uint8                `json:"status"`
}

type genesisValidatorMarshaling struct {
	Token      *math.HexOrDecimal256
	MainPubKey hexutil.Bytes
	BlsPubKey  hexutil.Bytes
	Role       uint8
}

type GenesisValidators map[common.Address]GenesisValidator // mainAddress => Validator

func (gv *GenesisValidators) UnmarshalJSON(data []byte) error {
	m := make(map[common.UnprefixedAddress]GenesisValidator)
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*gv = make(GenesisValidators)
	for addr, a := range m {
		if a.OperatorAddress == (common.Address{}) {
			a.OperatorAddress = common.Address(addr) //use address as default
		}
		(*gv)[common.Address(addr)] = a
	}
	return nil
}

// GenesisAlloc specifies the initial state that is part of the genesis block.
type GenesisAlloc map[common.Address]GenesisAccount

func (ga *GenesisAlloc) UnmarshalJSON(data []byte) error {
	m := make(map[common.UnprefixedAddress]GenesisAccount)
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*ga = make(GenesisAlloc)
	for addr, a := range m {
		(*ga)[common.Address(addr)] = a
	}
	return nil
}

// GenesisAccount is an account in the state of the genesis block.
type GenesisAccount struct {
	Code    []byte                      `json:"code,omitempty"`
	Storage map[common.Hash]common.Hash `json:"storage,omitempty"`
	Balance *big.Int                    `json:"balance" gencodec:"required"`
	Nonce   uint64                      `json:"nonce,omitempty"`
}

// field type overrides for gencodec
type genesisSpecMarshaling struct {
	Timestamp math.HexOrDecimal64
	ExtraData hexutil.Bytes
	Consensus hexutil.Bytes
	GasLimit  math.HexOrDecimal64
	GasUsed   math.HexOrDecimal64
	Number    math.HexOrDecimal64
	Alloc     map[common.UnprefixedAddress]GenesisAccount
}

type genesisAccountMarshaling struct {
	Code    hexutil.Bytes
	Balance *math.HexOrDecimal256
	Nonce   math.HexOrDecimal64
	Storage map[storageJSON]storageJSON
}

// storageJSON represents a 256 bit byte array, but allows less than 256 bits when
// unmarshaling from hex.
type storageJSON common.Hash

func (h *storageJSON) UnmarshalText(text []byte) error {
	text = bytes.TrimPrefix(text, []byte("0x"))
	if len(text) > 64 {
		return fmt.Errorf("too many hex characters in storage key/value %q", text)
	}
	offset := len(h) - len(text)/2 // pad on the left
	if _, err := hex.Decode(h[offset:], text); err != nil {
		fmt.Println(err)
		return fmt.Errorf("invalid hex storage key/value %q", text)
	}
	return nil
}

func (h storageJSON) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// GenesisMismatchError is raised when trying to overwrite an existing
// genesis block with an incompatible one.
type GenesisMismatchError struct {
	Stored, New common.Hash
}

func (e *GenesisMismatchError) Error() string {
	return fmt.Sprintf("database already contains an incompatible genesis block (have 0x%x, new 0x%x)", e.Stored, e.New)
}

// SetupGenesisBlock writes or updates the genesis block in db.
// The block that will be used is:
//
//                       genesis == nil       			genesis != nil
//                    +----------------------------------------------------------
//  db has no genesis | default-value by networkId 	|  genesis
//  db has genesis    | from DB           			|  from DB （will check whether the hashes are equal)
//
func SetupGenesisBlock(db youdb.Database, networkId uint64, genesis *Genesis) (gh common.Hash, err error) {
	if genesis != nil && genesis.NetworkId == 0 {
		return common.Hash{}, ErrGenesisNoNetworkId
	}
	// theFinalNetworkId is the networkId finally used when this function is succeed
	var theFinalNetworkId uint64
	defer func() {
		if err == nil {
			if theFinalNetworkId == 0 {
				err = errors.New("theFinalNetworkId not set")
			} else {
				params.InitNetworkId(theFinalNetworkId)
			}
		}
	}()

	// Just commit the new block if there is no stored genesis block.
	stored := rawdb.ReadCanonicalHash(db, 0)
	//note no 0'th block in db
	if (stored == common.Hash{}) {
		logging.Info("zero-block not found", "stored", stored.String())
		if genesis == nil {
			genesis = getDefaultGenesis(networkId)
			if genesis == nil {
				return common.Hash{}, fmt.Errorf("no default genesis for networkId: %d", networkId)
			}
			logging.Info("Writing default genesis block according to networkId")
		} else {
			logging.Info("Writing custom genesis block")
		}
		block, err := genesis.Commit(db)
		theFinalNetworkId = genesis.NetworkId

		if block == nil || err != nil {
			return common.Hash{}, err
		}

		logging.Info("genesis.Commit", "new block.Hash", block.Hash().String(), "root", block.Root().String(), "valRoot", block.ValRoot().String())
		logging.Info("new block.Header", common.AsJson(block.Header()), "<")
		logging.Info("new genesis", common.AsJson(genesis), "<")
		return block.Hash(), err
	}

	logging.Info("genesis block found", "hash", stored.String())
	// Check whether the genesis block is already written.
	if genesis != nil {
		hash := genesis.ToBlock(nil).Hash()
		logging.Info("genesis.Block.Hash", "hash", hash.String())
		if hash != stored {
			return hash, &GenesisMismatchError{stored, hash}
		}
	}

	// Get the existing networkId
	storedId := rawdb.ReadNetworkId(db, stored)
	if storedId == 0 {
		return stored, errors.New("no stored networkId while there is stored genesis hash")
	}
	theFinalNetworkId = storedId

	// Check config compatibility and write the config. Compatibility errors
	// are returned to the caller unless we're already at block zero.
	height := rawdb.ReadHeaderNumber(db, rawdb.ReadHeadHeaderHash(db))
	if height == nil {
		return stored, errors.New("missing block number for head header hash")
	}

	return stored, nil
}

// ToBlock creates the genesis block and writes state of a genesis specification
// to the given database (or discards it if nil).
func (g *Genesis) ToBlock(db youdb.Database) *types.Block {
	if db == nil {
		db = youdb.NewMemDatabase()
	}
	statedb, _ := state.New(common.Hash{}, common.Hash{}, common.Hash{}, state.NewDatabase(db))
	for addr, account := range g.Alloc {
		statedb.AddBalance(addr, account.Balance)
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}

	for _, v := range g.Validators {
		statedb.CreateValidator(v.Name, v.OperatorAddress, v.Coinbase, v.Role, v.MainPubKey, v.BlsPubKey, v.Token, params.YOUToStake(v.Token), 0, 0, 0, v.Status)
	}

	root, valRoot, stakingRoot := statedb.IntermediateRoot(true)
	head := &types.Header{
		Number:      new(big.Int).SetUint64(g.Number),
		Time:        g.Timestamp,
		ParentHash:  g.ParentHash,
		Extra:       g.ExtraData,
		Consensus:   g.Consensus,
		MixDigest:   g.Mixhash,
		Coinbase:    g.Coinbase,
		Root:        root,
		ValRoot:     valRoot,
		StakingRoot: stakingRoot,
		GasLimit:    g.GasLimit,
		GasUsed:     g.GasUsed,
		GasRewards:  big.NewInt(0),
		Subsidy:     big.NewInt(0),
		CurrVersion: g.CurrVersion,
	}

	statedb.Commit(true)
	statedb.Database().TrieDB().Commit(root, true)
	statedb.Database().TrieDB().Commit(valRoot, true)
	statedb.Database().TrieDB().Commit(stakingRoot, true)
	return types.NewBlock(head, nil, nil)
}

// Commit writes the block and state of a genesis specification to the database.
// The block is committed as the canonical head block.
func (g *Genesis) Commit(db youdb.Database) (*types.Block, error) {
	if err := g.PreCheck(); err != nil {
		return nil, err
	}
	block := g.ToBlock(db)
	if block.Number().Sign() != 0 {
		return nil, fmt.Errorf("can't commit genesis block with number > 0")
	}
	rawdb.WriteBlock(db, block)
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), nil)
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteHeadHeaderHash(db, block.Hash())

	rawdb.WriteNetworkId(db, block.Hash(), g.NetworkId)
	return block, nil
}

// MustCommit writes the genesis block and state to db, panicking on error.
// The block is committed as the canonical head block.
func (g *Genesis) MustCommit(db youdb.Database) *types.Block {
	block, err := g.Commit(db)
	if err != nil {
		panic(err)
	}
	return block
}

func (g *Genesis) PreCheck() error {
	emptyAddr := common.Address{}
	for key, v := range g.Validators {
		if v.OperatorAddress == emptyAddr {
			return fmt.Errorf("operatorAddress required. key=%s", key.String())
		}
		if v.Coinbase == emptyAddr {
			return fmt.Errorf("coinbase required. key=%s", key.String())
		}
	}
	return nil
}

// DefaultGenesisBlock returns the YOUChain main net genesis block.
func DefaultGenesisBlock() *Genesis {
	return &Genesis{
		NetworkId:   params.MainNetId,
		Consensus:   hexutil.MustDecode("0xf84e8001a05d93025288dddb431e3f43e07c63d1a96a28bf033457c74ee3f4d8eed88d3cf601a0010000000000000000000000000000000000000000000000000000000000000001801a8207d0820fa0"),
		GasLimit:    0x888888,
		Alloc:       decodePrealloc(mainnetAllocData),
		Validators:  decodeValidators(mainnetValidatorsData),
		CurrVersion: params.YouV1,
		Timestamp:   1589756160,
		Mixhash:     common.HexToHash("0x87c71741b903194ab0eb0bd581d5c522f0328e979f3c1bf29f6068bd2797fdf8"),
		ExtraData:   hexutil.MustDecode("0x46726f6d20746865203135746820746f2074686520313774682063656e747572792c206e657720726f757465732077657265206f70656e656420616e642065636f6e6f6d6963206163746976697469657320656e746572656420746865206d6f73742061637469766520706572696f642e"),
	}
}

// DefaultTestNetGenesisBlock returns the YOUChain public test-net genesis block.
func DefaultTestNetGenesisBlock() *Genesis {
	return &Genesis{
		NetworkId:   params.TestNetId,
		Consensus:   hexutil.MustDecode("0xf84e8001a05d93025288dddb431e3f43e07c63d1a96a28bf033457c74ee3f4d8eed88d3cf601a0010000000000000000000000000000000000000000000000000000000000000001801a8207d0820fa0"),
		GasLimit:    0x888888,
		Alloc:       decodePrealloc(testnetAllocData),
		Validators:  decodeValidators(testnetValidatorsData),
		CurrVersion: params.YouV1,
	}
}

// getDefaultGenesis returns the default genesis for a specific network.
// If the networkId is not predefined, the return will be nil
func getDefaultGenesis(networkId uint64) *Genesis {
	switch networkId {
	case params.MainNetId:
		return DefaultGenesisBlock()
	case params.TestNetId:
		return DefaultTestNetGenesisBlock()
	default:
		return nil
	}
}

func decodePrealloc(data string) GenesisAlloc {
	type storageItem struct {
		Key, Value common.Hash
	}
	type allocItem struct {
		Addr, Balance *big.Int
		StorageList   []storageItem
		Code          []byte
	}
	var p []allocItem
	if err := rlp.NewStream(strings.NewReader(data), 0).Decode(&p); err != nil {
		panic(err)
	}
	ga := make(GenesisAlloc, len(p))
	for _, account := range p {
		a := GenesisAccount{Balance: account.Balance}
		if len(account.StorageList) > 0 {
			a.Storage = make(map[common.Hash]common.Hash)
			for _, si := range account.StorageList {
				a.Storage[si.Key] = si.Value
			}
		}
		if len(account.Code) > 0 {
			a.Code = account.Code
		}
		ga[common.BigToAddress(account.Addr)] = a
	}
	return ga
}

func decodeValidators(data string) GenesisValidators {
	type valItem struct {
		Addr *big.Int
		Val  GenesisValidator
	}
	var p []valItem
	if err := rlp.NewStream(strings.NewReader(data), 0).Decode(&p); err != nil {
		panic(err)
	}
	gv := make(GenesisValidators, len(p))
	for _, val := range p {
		gv[common.BigToAddress(val.Addr)] = val.Val
	}
	return gv
}
