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
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/youchainhq/go-youchain/accounts"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/common/math"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/rawdb"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/core/vm"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/rpc"
)

const (
	defaultGasPrice = params.GLu
)

// CallArgs represents the arguments for a call.
type CallArgs struct {
	From     *common.Address `json:"from"`
	To       *common.Address `json:"to"`
	Gas      *hexutil.Uint64 `json:"gas"`
	GasPrice *hexutil.Big    `json:"gasPrice"`
	Value    *hexutil.Big    `json:"value"`
	Data     *hexutil.Bytes  `json:"data"`
}

// public api for main
type PublicMainApi struct {
	c         *Container
	nonceLock *AddrLocker
}

func NewPublicMainApi(c *Container, nonceLock *AddrLocker) *PublicMainApi {
	return &PublicMainApi{c, nonceLock}
}

// NetworkId is the network id for the current YOUChain network config.
func (y *PublicMainApi) NetworkId() hexutil.Uint64 {
	return (hexutil.Uint64)(params.NetworkId())
}

// Accounts returns the collection of accounts this node manages
func (y *PublicMainApi) Accounts() []common.Address {
	addresses := make([]common.Address, 0) // return [] instead of nil if empty
	for _, account := range y.c.accountManager.Accounts() {
		addresses = append(addresses, account.Address)
	}
	return addresses
}

// GetBalance returns the amount of lu for the given address in the state of the
// given block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta
// block numbers are also allowed.
func (y *PublicMainApi) GetBalance(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (*hexutil.Big, error) {
	state, _, err := y.c.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}
	return (*hexutil.Big)(state.GetBalance(address)), state.Error()
}

func (y *PublicMainApi) BlockNumber() (hexutil.Uint64, error) {
	header, _ := y.c.HeaderByNumber(context.Background(), rpc.LatestBlockNumber) // latest header should always be available
	return hexutil.Uint64(header.Number.Uint64()), nil
}

func (y *PublicMainApi) GasPrice(ctx context.Context) (*hexutil.Big, error) {
	price, err := y.c.SuggestPrice(ctx)
	return (*hexutil.Big)(price), err
}

func (y *PublicMainApi) GetBlockByHash(ctx context.Context, hash string, fullTx bool) (map[string]interface{}, error) {
	if block := y.c.youChain.BlockChain().GetBlockByHash(common.HexToHash(hash)); block != nil {
		return RPCMarshalBlock(block, true, fullTx)
	}
	return nil, errors.New("block not found")
}

// GetBlockByNumber returns the requested block. When blockNr is -1 the chain head is returned. When fullTx is true all
// transactions in the block are returned in full detail, otherwise only the transaction hash is returned.
func (y *PublicMainApi) GetBlockByNumber(ctx context.Context, blockNr rpc.BlockNumber, fullTx bool) (map[string]interface{}, error) {
	block, _ := y.c.BlockByNumber(ctx, blockNr)
	if block != nil {
		response, err := RPCMarshalBlock(block, true, fullTx)
		if err == nil && blockNr == rpc.PendingBlockNumber {
			// Pending blocks need to nil out a few fields
			for _, field := range []string{"hash", "nonce", "miner"} {
				response[field] = nil
			}
		}
		return response, err
	}
	return nil, errors.New("block not found")
}

// GetTransactionCount returns the number of transactions the given address has sent for the given block number
func (y *PublicMainApi) GetTransactionCount(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (*hexutil.Uint64, error) {
	if blockNr == rpc.PendingBlockNumber {
		nonce := y.c.youChain.TxPool().Nonce(address)
		return (*hexutil.Uint64)(&nonce), nil
	}

	state, _, err := y.c.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}
	nonce := state.GetNonce(address)
	return (*hexutil.Uint64)(&nonce), state.Error()
}

func (y *PublicMainApi) GetPoolNonce(address string) (*hexutil.Uint64, error) {
	nonce := y.c.youChain.TxPool().Nonce(common.HexToAddress(address))
	return (*hexutil.Uint64)(&nonce), nil
}

func (y *PublicMainApi) GetTransactionByHash(txHash common.Hash) (*RPCTransaction, error) {
	// Try to return an already finalized transaction
	tx, blockHash, blockNumber, index, err := y.c.GetTransaction(txHash)
	if err != nil {
		return nil, err
	}
	if tx != nil {
		return newRPCTransaction(tx, blockHash, blockNumber, index), nil
	}
	// No finalized transaction, try to retrieve it from the pool
	if tx := y.c.GetPoolTransaction(txHash); tx != nil {
		return newRPCPendingTransaction(tx), nil
	}
	return nil, errors.New("tx not found")
}

func (y *PublicMainApi) GetTransactionByBlockHashAndIndex(blockHash common.Hash, index hexutil.Uint) (*RPCTransaction, error) {
	if block := y.c.youChain.BlockChain().GetBlockByHash(blockHash); block != nil {
		return newRPCTransactionFromBlockIndex(block, uint64(index)), nil
	}
	return nil, errors.New("block not found")
}

// GetTransactionByBlockNumberAndIndex returns the transaction for the given block number and index.
func (y *PublicMainApi) GetTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) (*RPCTransaction, error) {
	if block, _ := y.c.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCTransactionFromBlockIndex(block, uint64(index)), nil
	}
	return nil, errors.New("block not found")
}

func (y *PublicMainApi) GetBlockTransactionCountByHash(hash common.Hash) (*hexutil.Uint, error) {
	if block := y.c.youChain.BlockChain().GetBlockByHash(hash); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n, nil
	}
	return nil, nil
}

// GetBlockTransactionCountByNumber returns the number of transactions in the block with the given block number.
func (y *PublicMainApi) GetBlockTransactionCountByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*hexutil.Uint, error) {
	if block, _ := y.c.BlockByNumber(ctx, blockNr); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n, nil
	}
	return nil, nil
}

// GetCode returns the code stored at the given address in the state for the given block number.
func (y *PublicMainApi) GetCode(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (hexutil.Bytes, error) {
	state, _, err := y.c.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}
	code := state.GetCode(address)
	return code, state.Error()
}

// GetStorageAt returns the storage from the state at the given address, key and
// block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta block
// numbers are also allowed.
func (y *PublicMainApi) GetStorageAt(ctx context.Context, address common.Address, key string, blockNr rpc.BlockNumber) (hexutil.Bytes, error) {
	state, _, err := y.c.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}
	res := state.GetState(address, common.HexToHash(key))
	return res[:], state.Error()
}

func (y *PublicMainApi) SendSignedTransaction(signedTx *types.Transaction) (string, error) {
	err := y.c.youChain.TxPool().AddLocal(signedTx)
	if err != nil {
		signer := types.MakeSigner(y.c.youChain.BlockChain().CurrentBlock().Number())
		from, _ := types.Sender(signer, signedTx)
		logging.Info("err_in_addtx", "from", from.String(), "to", signedTx.To().String(),
			"value", signedTx.Value().String(), "nonce", signedTx.Nonce(), "hash", signedTx.Hash().String(), "err", err.Error())
		return "error in send tx", err
	}
	return signedTx.Hash().String(), nil
}

// SendTransaction creates a transaction for the given argument, sign it and submit it to the
// transaction pool.
func (y *PublicMainApi) SendTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) {
	account := accounts.Account{Address: args.From}

	_, found := y.c.accountManager.Find(account.Address)
	if !found {
		return common.Hash{}, accounts.ErrUnknownAccount
	}

	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		y.nonceLock.LockAddr(args.From)
		defer y.nonceLock.UnlockAddr(args.From)
	}

	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, y.c); err != nil {
		return common.Hash{}, err
	}
	tx := args.toTransaction()
	signed, err := y.c.accountManager.SignTx(account, tx)
	if err != nil {
		return common.Hash{}, err
	}

	if err := y.c.youChain.TxPool().AddLocal(signed); err != nil {
		return common.Hash{}, err
	}

	if signed.To() == nil {
		signer := types.MakeSigner(y.c.youChain.BlockChain().CurrentBlock().Number())
		from, err := types.Sender(signer, signed)
		if err != nil {
			return common.Hash{}, err
		}
		addr := crypto.CreateAddress(from, signed.Nonce())
		logging.Info("Submitted contract creation", "fullhash", signed.Hash().Hex(), "contract", addr.Hex())
	} else {
		logging.Info("Submitted transaction", "fullhash", signed.Hash().Hex(), "recipient", signed.To().String())
	}
	return signed.Hash(), nil
}

// SendRawTransaction will add the signed transaction to the transaction pool.
// The sender is responsible for signing the transaction and using the correct nonce.
func (y *PublicMainApi) SendRawTransaction(encodedTx hexutil.Bytes) (common.Hash, error) {
	tx := new(types.Transaction)
	if err := rlp.DecodeBytes(encodedTx, tx); err != nil {
		return common.Hash{}, err
	}

	if err := y.c.youChain.TxPool().AddLocal(tx); err != nil {
		return common.Hash{}, err
	}

	if tx.To() == nil {
		signer := types.MakeSigner(y.c.youChain.BlockChain().CurrentBlock().Number())
		from, err := types.Sender(signer, tx)
		if err != nil {
			return common.Hash{}, err
		}
		addr := crypto.CreateAddress(from, tx.Nonce())
		logging.Info("Submitted contract creation", "fullhash", tx.Hash().Hex(), "contract", addr.Hex())
	} else {
		logging.Info("Submitted transaction", "fullhash", tx.Hash().Hex(), "recipient", tx.To().String())
	}
	return tx.Hash(), nil
}

func DoCall(ctx context.Context, c *Container, args CallArgs, blockNr rpc.BlockNumber, vmLocalCfg vm.LocalConfig, timeout time.Duration, globalGasCap *big.Int, overrideBalance bool) ([]byte, uint64, bool, error) {
	defer func(start time.Time) { logging.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	state, header, err := c.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, 0, false, err
	}
	// Set sender address or use a default if none specified
	var addr common.Address
	if args.From == nil {
		if accs := c.accountManager.Accounts(); len(accs) > 0 {
			addr = accs[0].Address
		}
	} else {
		addr = *args.From
	}

	gas := uint64(math.MaxUint64 / 2)
	if args.Gas != nil {
		gas = uint64(*args.Gas)
	}
	if globalGasCap != nil && globalGasCap.Uint64() < gas {
		logging.Warn("Caller gas above allowance, capping", "requested", gas, "cap", globalGasCap)
		gas = globalGasCap.Uint64()
	}
	gasPrice := new(big.Int).SetUint64(defaultGasPrice)
	if args.GasPrice != nil {
		gasPrice = args.GasPrice.ToInt()
	}

	value := new(big.Int)
	if args.Value != nil {
		value = args.Value.ToInt()
	}

	var data []byte
	if args.Data != nil {
		data = []byte(*args.Data)
	}

	logging.Info("doCall", "gas", gas, "gasPrice", gasPrice.String())
	msg := types.NewMessage(addr, args.To, 0, value, gas, gasPrice, data, false)

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	vmCfg, err := core.PrepareVMConfig(c.youChain.BlockChain(), header.Number.Uint64(), vmLocalCfg)
	if err != nil {
		return nil, 0, false, err
	}
	vmCfg.SetCancelContext(ctx, cancel)

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	if overrideBalance {
		state.SetBalance(addr, math.MaxBig256)
	}
	res, gas, failed, err := c.processor.ApplyMessageEntry(msg, state, c.youChain.BlockChain(), header, nil, gp, vmCfg)

	if err == core.ErrCancelled {
		return nil, 0, false, fmt.Errorf("execution aborted (timeout = %v)", timeout)
	}
	return res, gas, failed, err
}

// Call executes the given transaction on the state for the given block number.
// It doesn't make and changes in the state/blockchain and is useful to execute and retrieve values.
func (y *PublicMainApi) Call(ctx context.Context, args CallArgs, blockNr rpc.BlockNumber) (hexutil.Bytes, error) {
	result, _, _, err := DoCall(ctx, y.c, args, blockNr, vm.LocalConfig{}, 5*time.Second, y.c.RPCGasCap(), true)
	return (hexutil.Bytes)(result), err
}

func DoEstimateGas(ctx context.Context, c *Container, args CallArgs, blockNr rpc.BlockNumber, gasCap *big.Int) (hexutil.Uint64, error) {
	// Binary search the gas requirement, as it may be higher than the amount used
	var (
		lo  uint64 = params.TxGas - 1
		hi  uint64
		cap uint64
	)
	if blockNr == rpc.PendingBlockNumber && !c.youChain.Miner().Mining() {
		// only the working miner has pending block. if the miner is not working, change to the latest block.
		blockNr = rpc.LatestBlockNumber
	}
	logging.Info("DoEstimateGas", "height", blockNr.Int64(), "gasCap", gasCap)
	if args.Gas != nil && uint64(*args.Gas) >= params.TxGas {
		hi = uint64(*args.Gas)
	} else {
		// Retrieve the block to act as the gas ceiling
		block, err := c.BlockByNumber(ctx, blockNr)
		if err != nil {
			return 0, err
		}
		hi = block.GasLimit()
	}

	if gasCap != nil && hi > gasCap.Uint64() {
		logging.Warn("Caller gas above allowance, capping", "requested", hi, "cap", gasCap)
		hi = gasCap.Uint64()
	}
	cap = hi
	logging.Info("DoEstimateGas", "height", blockNr.Int64(), "gasCap", gasCap, "cap", cap)
	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(gas uint64) bool {
		args.Gas = (*hexutil.Uint64)(&gas)
		logging.Info("DoEstimateGas start doCall", "height", blockNr.Int64(), "gasCap", gasCap, "cap", cap)
		_, _, failed, err := DoCall(ctx, c, args, blockNr, vm.LocalConfig{}, 0, gasCap, false)
		if err != nil || failed {
			logging.Error("DoEstimateGas failed", "err", err, "failed", failed)
			return false
		}
		return true
	}
	// Execute the binary search and hone in on an executable gas limit
	for lo+1 < hi {
		mid := (hi + lo) / 2
		if !executable(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	// Reject the transaction as invalid if it still fails at the highest allowance
	if hi == cap {
		if !executable(hi) {
			return 0, fmt.Errorf("gas required exceeds allowance (%d) or always failing transaction", cap)
		}
	}
	return hexutil.Uint64(hi), nil
}

// EstimateGas returns an estimate of the amount of gas needed to execute the
// given transaction against the current pending block.
func (y *PublicMainApi) EstimateGas(ctx context.Context, args CallArgs) (hexutil.Uint64, error) {
	return DoEstimateGas(ctx, y.c, args, rpc.PendingBlockNumber, y.c.RPCGasCap())
}

// GetTransactionReceipt returns the transaction receipt for the given transaction hash.
func (y *PublicMainApi) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	tx, blockHash, blockNumber, index := rawdb.ReadTransaction(y.c.ChainDb(), hash)
	if tx == nil {
		return nil, nil
	}
	receipts, err := y.c.GetReceipts(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	if len(receipts) <= int(index) {
		return nil, nil
	}
	receipt := receipts[index]

	var signer = types.MakeSigner(y.c.youChain.BlockChain().CurrentBlock().Number())
	from, _ := types.Sender(signer, tx)

	fields := receiptJsonMap(receipt, hash, blockNumber)
	fields["transactionHash"] = hash
	fields["transactionIndex"] = hexutil.Uint64(index)
	fields["from"] = from
	fields["to"] = tx.To()

	return fields, nil
}

func receiptJsonMap(receipt *types.Receipt, blockHash common.Hash, blockNumber uint64) map[string]interface{} {
	fields := map[string]interface{}{
		"blockHash":         blockHash,
		"blockNumber":       hexutil.Uint64(blockNumber),
		"gasUsed":           hexutil.Uint64(receipt.GasUsed),
		"cumulativeGasUsed": hexutil.Uint64(receipt.CumulativeGasUsed),
		"contractAddress":   nil,
		"logs":              receipt.Logs,
		"logsBloom":         receipt.Bloom,
	}

	// Assign receipt status or post state.
	if len(receipt.PostState) > 0 {
		fields["root"] = hexutil.Bytes(receipt.PostState)
	} else {
		fields["status"] = hexutil.Uint(receipt.Status)
	}
	if receipt.Logs == nil {
		fields["logs"] = [][]*types.Log{}
	}
	// If the ContractAddress is 20 0x0 bytes, assume it is not a contract creation
	if receipt.ContractAddress != (common.Address{}) {
		fields["contractAddress"] = receipt.ContractAddress
	}
	return fields
}

func (y *PublicMainApi) GetStakingEndBlockReceipt(ctx context.Context, blockNr rpc.BlockNumber) (map[string]interface{}, error) {
	if blockNr == rpc.PendingBlockNumber {
		return nil, errors.New("no end-block receipt for pending-block")
	}
	block, err := y.c.BlockByNumber(ctx, blockNr)
	if err != nil {
		return nil, err
	}
	receipts, err := y.c.GetReceipts(ctx, block.Hash())
	if err != nil {
		return nil, err
	}
	var receipt *types.Receipt
	for i := len(receipts) - 1; i >= 0; i-- {
		if receipts[i].TxHash != (common.Hash{}) {
			break
		}
		if receipts[i].ContractAddress == params.StakingModuleAddress {
			receipt = receipts[i]
			break
		}
	}
	if receipt == nil {
		logging.Info("no staking end-block receipt", "block-number", blockNr)
		return nil, nil
	}

	fields := receiptJsonMap(receipt, block.Hash(), block.NumberU64())
	fields["to"] = params.StakingModuleAddress
	return fields, nil
}

// Sign calculates an ECDSA signature for:
// keccack256("\x19Ethereum Signed Message:\n" + len(message) + message).
//
// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
// where the V value will be 27 or 28 for legacy reasons.
//
// The account associated with addr must be unlocked.
func (y *PublicMainApi) Sign(addr common.Address, data hexutil.Bytes) (hexutil.Bytes, error) {
	// Look up the wallet containing the requested signer
	account, found := y.c.accountManager.Find(accounts.Account{Address: addr}.Address)
	if !found {
		return nil, accounts.ErrUnknownAccount
	}
	// Sign the requested hash with the wallet
	signature, err := y.c.accountManager.SignHash(*account, signHash(data))
	if err == nil {
		signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
	}
	return signature, err
}

type P2PStatus struct {
	Hosts     []string `json:"hosts"`
	PeerId    string   `json:"peer_id"`
	NetworkId uint64   `json:"network_id"`
}

// Result structs for GetProof
type AccountResult struct {
	Address      common.Address  `json:"address"`
	AccountProof []string        `json:"accountProof"`
	Balance      *hexutil.Big    `json:"balance"`
	CodeHash     common.Hash     `json:"codeHash"`
	Nonce        hexutil.Uint64  `json:"nonce"`
	StorageHash  common.Hash     `json:"storageHash"`
	StorageProof []StorageResult `json:"storageProof"`
}
type StorageResult struct {
	Key   string       `json:"key"`
	Value *hexutil.Big `json:"value"`
	Proof []string     `json:"proof"`
}

// GetProof returns the Merkle-proof for a given account and optionally some storage keys.
func (y *PublicMainApi) GetProof(ctx context.Context, address common.Address, storageKeys []string, blockNr rpc.BlockNumber) (*AccountResult, error) {
	state, _, err := y.c.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}

	storageTrie := state.StorageTrie(address)
	storageHash := types.EmptyRootHash
	codeHash := state.GetCodeHash(address)
	storageProof := make([]StorageResult, len(storageKeys))

	// if we have a storageTrie, (which means the account exists), we can update the storagehash
	if storageTrie != nil {
		storageHash = storageTrie.Hash()
	} else {
		// no storageTrie means the account does not exist, so the codeHash is the hash of an empty bytearray.
		codeHash = crypto.Keccak256Hash(nil)
	}

	// create the proof for the storageKeys
	for i, key := range storageKeys {
		if storageTrie != nil {
			proof, storageError := state.GetStorageProof(address, common.HexToHash(key))
			if storageError != nil {
				return nil, storageError
			}
			storageProof[i] = StorageResult{key, (*hexutil.Big)(state.GetState(address, common.HexToHash(key)).Big()), common.ToHexArray(proof)}
		} else {
			storageProof[i] = StorageResult{key, &hexutil.Big{}, []string{}}
		}
	}

	// create the accountProof
	accountProof, proofErr := state.GetProof(address)
	if proofErr != nil {
		return nil, proofErr
	}

	return &AccountResult{
		Address:      address,
		AccountProof: common.ToHexArray(accountProof),
		Balance:      (*hexutil.Big)(state.GetBalance(address)),
		CodeHash:     codeHash,
		Nonce:        hexutil.Uint64(state.GetNonce(address)),
		StorageHash:  storageHash,
		StorageProof: storageProof,
	}, state.Error()
}

// YouVersion returns the current YOU protocol version this node supports
func (y *PublicMainApi) ProtocolVersion() hexutil.Uint {
	return hexutil.Uint(y.c.ProtocolVersion())
}

func (y *PublicMainApi) Syncing() (interface{}, error) {
	progress := y.c.youChain.ProtocolManager().Downloader().Progress()

	// Return not syncing if the synchronisation already completed
	if progress.CurrentBlock >= progress.HighestBlock {
		return false, nil
	}
	// Otherwise gather the block sync stats
	return map[string]interface{}{
		"startingBlock": hexutil.Uint64(progress.StartingBlock),
		"currentBlock":  hexutil.Uint64(progress.CurrentBlock),
		"highestBlock":  hexutil.Uint64(progress.HighestBlock),
		"pulledStates":  hexutil.Uint64(progress.PulledStates),
		"knownStates":   hexutil.Uint64(progress.KnownStates),
	}, nil
}

func (y *PublicMainApi) Mining() bool {
	return y.c.youChain.Miner().Mining()
}
