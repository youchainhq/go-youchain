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

package youapi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/youchainhq/go-youchain/bls"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/internal/debug"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/rpc"
	"github.com/youchainhq/go-youchain/staking"
)

// private api for dev
type PrivateDevApi struct {
	c *Container
}

func NewPrivateDevApi(c *Container) *PrivateDevApi {
	return &PrivateDevApi{c}
}

// StateDump retrieves the trie in the stateDB.
// dev_stateDump
func (api *PrivateDevApi) StateDump() (state.Dump, error) {
	db, err := api.c.youChain.BlockChain().State()
	if err != nil {
		return state.Dump{}, err
	}
	json := db.RawDump()

	return json, nil
}

func (api *PrivateDevApi) StateDumpByNumber(ctx context.Context, blockNr rpc.BlockNumber) (state.Dump, error) {
	db, _, err := api.c.StateAndHeaderByNumber(ctx, blockNr)
	if db == nil || err != nil {
		return state.Dump{}, err
	}
	json := db.RawDump()

	return json, nil
}

// newRPCPendingTransaction returns a pending transaction that will serialize to the RPC representation
func newRPCPendingTransaction(tx *types.Transaction) *RPCTransaction {
	return newRPCTransaction(tx, common.Hash{}, 0, 0)
}

// StateLogDump retrieves all logs in the stateDB.
// dev_stateLogDump
func (api *PrivateDevApi) StateLogDump() (state.DumpAllLogs, error) {
	state, err := api.c.youChain.BlockChain().State()
	if err != nil {
		panic(err)
	}
	json, err := state.LogDump()
	if err != nil {
		panic(err)
	}
	return json, nil
}

// Rewind rewinds the local chain to a new head. Everything above the new
// head will be deleted and the new one set.
// dev_rewind
func (api *PrivateDevApi) SetHead(number uint64) error {
	miner := api.c.youChain.Miner()
	miner.Stop()
	err := api.c.youChain.BlockChain().SetHead(number)
	miner.Start()
	return err
}

func (api *PrivateDevApi) SendRawTransactions(encodedTxs []hexutil.Bytes) ([]string, error) {
	txs := make([]*types.Transaction, 0, len(encodedTxs))
	var txsHash = make([]string, len(txs))
	for _, encodedTx := range encodedTxs {
		tx := new(types.Transaction)
		if err := rlp.DecodeBytes(encodedTx, tx); err != nil {
			return txsHash, err
		}
		txs = append(txs, tx)
	}

	if len(txs) == 0 {
		return txsHash, fmt.Errorf("no txs received")
	}

	errs := api.c.youChain.TxPool().AddLocals(txs)
	for i, e := range errs {
		if e != nil {
			logging.Error("AddLocals", "err", e)
			txsHash = append(txsHash, (common.Hash{}).String())
		} else {
			txsHash[i] = txs[i].Hash().String()
		}
	}

	return txsHash, nil
}

func (api *PrivateDevApi) SendTransactions(signedTxs []*types.Transaction) ([]string, error) {
	var txsHash = make([]string, len(signedTxs))
	if len(signedTxs) == 0 {
		return txsHash, fmt.Errorf("no txs received")
	}

	proc := time.Now()
	errs := api.c.youChain.TxPool().AddLocals(signedTxs)

	defer func() {
		logging.Debug("add txs", "count", len(signedTxs), "elapsed", time.Since(proc))
	}()

	for i, e := range errs {
		if e != nil {
			logging.Error("add txs failed", "err", e)
			txsHash[i] = (common.Hash{}).String()
		} else {
			txsHash[i] = signedTxs[i].Hash().String()
		}
	}
	logging.Info("sendTransactions", "info", txsHash)
	return txsHash, nil
}

func (api *PrivateDevApi) SetPrintOrigin(print bool) error {
	debug.PrintOrigin(print)
	return nil
}

func (api *PrivateDevApi) Verbosity(verbosity int) error {
	debug.Verbosity(verbosity)
	return nil
}

func (api *PrivateDevApi) Vmodule(vmodule string) error {
	return debug.Vmodule(vmodule)
}

func (api *PrivateDevApi) Exit() error {
	t := time.NewTimer(10 * time.Second)
	errc := make(chan error)
	go func() {
		errc <- api.c.node.Stop()
	}()

	select {
	case err := <-errc:
		if err != nil {
			logging.Error("stop node", "err", err)
		}
	case <-t.C:
		logging.Error("stop node timeout")
	}
	os.Exit(0)
	return nil
}

func (api *PrivateDevApi) Stop() error {
	go api.c.node.Stop()
	return nil
}

func int32ToBytes(i uint32) []byte {
	var buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, i)
	return buf
}

func (y *PrivateDevApi) DoubleSign(ctx context.Context, skey hexutil.Bytes, blskey hexutil.Bytes, next uint64) (map[string]interface{}, error) {
	blsmgr := bls.NewBlsManager()
	blsSk, err := blsmgr.DecSecretKey(blskey)
	if err != nil {
		return nil, err
	}
	rawSk, err := crypto.ToECDSA(skey)
	if err != nil {
		return nil, err
	}
	consAddr := crypto.PubkeyToAddress(rawSk.PublicKey)
	logging.Info("double sign", "consAddr", consAddr.String())

	currentHeader := y.c.youChain.BlockChain().CurrentHeader()
	round := new(big.Int).Add(currentHeader.Number, new(big.Int).SetUint64(next))
	var roundIndex uint32 = 1

	hash0 := common.BigToHash(big.NewInt(1))
	hash1 := common.BigToHash(big.NewInt(2))
	payload0 := append(hash0.Bytes(), append(round.Bytes(), int32ToBytes(roundIndex)...)...) ////append(blockHash.Bytes(), int32ToBytes(vote.Votes)...)
	payload1 := append(hash1.Bytes(), append(round.Bytes(), int32ToBytes(roundIndex)...)...) ////append(blockHash.Bytes(), int32ToBytes(vote.Votes)...)

	vldReader, err := y.c.youChain.BlockChain().LookBackVldReaderForRound(round.Uint64(), false)
	if err != nil {
		return nil, err
	}
	idx, exist := vldReader.GetValidators().GetIndex(consAddr)
	if !exist {
		return nil, errors.New("validator not exist")
	}

	sig0 := blsSk.Sign(payload0).Compress().Bytes()
	sig1 := blsSk.Sign(payload1).Compress().Bytes()

	y.c.EventMux().AsyncPost(staking.NewEvidence(staking.EvidenceDoubleSignV5{
		Round:      round.Uint64(),
		RoundIndex: 1,
		SignerIdx:  uint32(idx),
		VoteType:   2,
		Signs: []*staking.SignInfo{
			{hash0, sig0},
			{hash1, sig1},
		},
	}))
	ret := make(map[string]interface{})
	ret["round"] = round
	ret["roundIndex"] = roundIndex
	ret["signerIdx"] = idx
	ret["signs"] = map[string]string{
		common.BigToHash(big.NewInt(1)).String(): hexutil.Encode(sig0),
		common.BigToHash(big.NewInt(2)).String(): hexutil.Encode(sig1),
	}
	return ret, nil
}
