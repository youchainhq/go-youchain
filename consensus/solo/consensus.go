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

package solo

import (
	"crypto/ecdsa"
	"errors"
	"github.com/hashicorp/golang-lru"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/event"
	"math/big"
	"time"
)

const (
	StakeLookBack = 100
)

type Solo struct {
	sealer       bool
	nodeIdx      uint64
	totalNodes   uint64
	blockTime    time.Duration
	chain        consensus.ChainReader
	stateDBCache *lru.Cache
}

func (s *Solo) GetLookBackBlockNumber(num *big.Int) *big.Int {
	if num.Sign() < 0 {
		panic("Error num")
	}
	lookBack := big.NewInt(0).Set(num)
	cfg := big.NewInt(int64(StakeLookBack))
	if num.Cmp(cfg) > 0 {
		lookBack = lookBack.Sub(lookBack, cfg)
	} else {
		lookBack.SetInt64(0)
	}
	return lookBack
}

func (s *Solo) CheckValidatorVotes(chain consensus.ChainReader, header *types.Header) (map[common.Address]bool, error) {
	data := make(map[common.Address]bool)
	return data, nil
}

func (s *Solo) SetChain(chain consensus.ChainReader) {
	s.chain = chain
}

func NewFallbackSolo(sealer bool, nodeIdx uint64, totalNodes uint64, blockTime time.Duration) *Solo {
	return &Solo{sealer: sealer, nodeIdx: nodeIdx, totalNodes: totalNodes, blockTime: blockTime}
}

func (s *Solo) Update(sealer bool, nodeIdx uint64, totalNodes uint64) {
	s.sealer = sealer
	s.nodeIdx = nodeIdx
	s.totalNodes = totalNodes
}

func NewSolo() *Solo {
	d := &Solo{}
	d.stateDBCache, _ = lru.New(10)
	return d
}

func (s *Solo) Author(header *types.Header) (common.Address, error) {
	return common.Address{}, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules of a
// given engine. Verifying the seal may be done optionally here, or explicitly
// via the VerifySeal method.
func (s *Solo) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return nil
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications (the order is that of
// the input slice).
func (s *Solo) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	go func() {
		for range headers {
			select {
			case <-abort:
				return
			case results <- nil:
			}
		}
	}()
	return abort, results
}

// VerifySeal checks whether the crypto seal on a header is valid according to
// the consensus rules of the given engine.
func (s *Solo) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return nil
}

// Seal generates a new block for the given input block with the local miner's
// seal place on top.
func (s *Solo) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	t := time.NewTimer(s.blockTime)

	for {
		select {
		case <-t.C:
			return block, nil
		case <-stop:

			return nil, nil
		}
	}
}

//todo update here
func (s *Solo) UpdateContextForNewBlock(block *types.Block) error {
	return nil
}

func (s *Solo) Prepare(chain consensus.ChainReader, header *types.Header) error {
	if s.sealer {
		return nil
	} else {
		return errors.New("not allow to seal")
	}
}

func (s *Solo) Finalize(chain consensus.ChainReader, header *types.Header, statedb *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt) {
	//no rewards in Solo, do nothing.
}

func (s *Solo) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt) (*types.Block, error) {
	header.Root, header.ValRoot, header.StakingRoot = state.IntermediateRoot(true)
	return types.NewBlock(header, txs, receipts), nil
}

// TODO: fork-selection rules
//   -1 if blockA <  blockB
//    0 if blockA == blockB
//   +1 if blockA >  blockB
//
func (s *Solo) CompareBlocks(blockA *types.Block, blockB *types.Block) int {
	return int(0)
}

func (s *Solo) SetValKey(sk *ecdsa.PrivateKey, blsKeyBytes []byte) (err error) {
	return nil
}

func (s *Solo) GetValMainAddress() common.Address {
	return common.Address{}
}

func (s *Solo) StartMining(chain consensus.ChainReader, inserter consensus.MineInserter, eventMux *event.TypeMux) error {
	return nil
}

func (s *Solo) Restart() error {
	return nil
}

func (s *Solo) Stop() error {
	//do nothing
	return nil
}
