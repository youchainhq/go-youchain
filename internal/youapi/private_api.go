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
	"time"

	"github.com/youchainhq/go-youchain/accounts"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/common/math"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/rlp"
)

// private api for personal

type PrivateAccountApi struct {
	c         *Container
	nonceLock *AddrLocker
}

func NewPrivateAccountApi(c *Container, nonceLock *AddrLocker) *PrivateAccountApi {
	return &PrivateAccountApi{c, nonceLock}
}

// NewAccount will create a new account and returns the address for the new account.
func (y *PrivateAccountApi) NewAccount(password string) (common.Address, error) {
	acc, err := y.c.accountManager.NewAccount([]byte(password))
	if err == nil {
		return acc.Address, err
	}
	return common.Address{}, nil
}

// ListAccounts will return a list of addresses for accounts this node manages.
func (y *PrivateAccountApi) ListAccounts() []common.Address {
	addresses := make([]common.Address, 0) // return [] instead of nil if empty
	for _, account := range y.c.accountManager.Accounts() {
		addresses = append(addresses, account.Address)
	}
	return addresses
}

// LockAccount will lock the account associated with the given address when it's unlocked.
func (y *PrivateAccountApi) LockAccount(addr common.Address) bool {
	err := y.c.accountManager.Lock(addr)
	return err == nil
}

// UnlockAccount will unlock the account associated with the given address with
// the given password for duration seconds. If duration is nil it will use a
// default of 300 seconds. It returns an indication if the account was unlocked.
func (y *PrivateAccountApi) UnlockAccount(addr common.Address, password string, duration *uint64) (bool, error) {
	const max = uint64(time.Duration(math.MaxInt64) / time.Second)
	var d time.Duration
	if duration == nil {
		d = 300 * time.Second
	} else if *duration > max {
		return false, errors.New("unlock duration too large")
	} else {
		d = time.Duration(*duration) * time.Second
	}
	account, found := y.c.accountManager.Find(addr)
	if !found {
		return false, accounts.ErrUnknownAccount
	}
	err := y.c.accountManager.TimedUnlock(account, password, d)
	if err != nil {
		logging.Warn("Failed account unlock attempt", "address", addr, "err", err)
	}
	return err == nil, err
}

// ImportRawKey stores the given hex encoded ECDSA key into the key directory,
// encrypting it with the passphrase.
func (y *PrivateAccountApi) ImportRawKey(privkey string, password string) (common.Address, error) {
	key, err := crypto.HexToECDSA(privkey)
	if err != nil {
		return common.Address{}, err
	}
	acc, err := y.c.accountManager.ImportECDSA(key, password)
	return acc.Address, err
}

// signTransaction sets defaults and signs the given transaction
// NOTE: the caller needs to ensure that the nonceLock is held, if applicable,
// and release it after the transaction has been submitted to the tx pool
func (y *PrivateAccountApi) SendTransaction(ctx context.Context, args SendTxArgs, passwd string) (common.Hash, error) {

	signed, err := y.signTransaction(ctx, &args, passwd)
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

// signTransaction sets defaults and signs the given transaction
// NOTE: the caller needs to ensure that the nonceLock is held, if applicable,
// and release it after the transaction has been submitted to the tx pool
func (y *PrivateAccountApi) signTransaction(ctx context.Context, args *SendTxArgs, passwd string) (*types.Transaction, error) {
	account, found := y.c.accountManager.Find(accounts.Account{Address: args.From}.Address)
	if !found {
		return nil, accounts.ErrUnknownAccount
	}

	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		y.nonceLock.LockAddr(args.From)
		defer y.nonceLock.UnlockAddr(args.From)
	}

	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, y.c); err != nil {
		return nil, err
	}
	tx := args.toTransaction()
	signed, err := y.c.accountManager.SignTxWithPassphrase(*account, passwd, tx)
	return signed, err
}

// SignTransactionResult represents a RLP encoded signed transaction.
type SignTransactionResult struct {
	Raw hexutil.Bytes      `json:"raw"`
	Tx  *types.Transaction `json:"tx"`
}

// SignTransaction will create a transaction from the given arguments and
// tries to sign it with the key associated with args.To. If the given passwd isn't
// able to decrypt the key it fails. The transaction is returned in RLP-form, not broadcast
// to other nodes
func (y *PrivateAccountApi) SignTransaction(ctx context.Context, args SendTxArgs, passwd string) (*SignTransactionResult, error) {
	// No need to obtain the noncelock mutex, since we won't be sending this
	// tx into the transaction pool, but right back to the user
	if args.Gas == nil {
		return nil, fmt.Errorf("gas not specified")
	}
	if args.GasPrice == nil {
		return nil, fmt.Errorf("gasPrice not specified")
	}
	if args.Nonce == nil {
		return nil, fmt.Errorf("nonce not specified")
	}
	signed, err := y.signTransaction(ctx, &args, passwd)
	if err != nil {
		logging.Warn("Failed transaction sign attempt", "from", args.From, "to", args.To, "value", args.Value.ToInt(), "err", err)
		return nil, err
	}
	data, err := rlp.EncodeToBytes(signed)
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, signed}, nil
}

// This gives context to the signed message and prevents signing of transactions.
func signHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19YOUChain Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}

// Sign calculates an YOUChain ECDSA signature for:
// keccack256("\x19YOUChain Signed Message:\n" + len(message) + message))
//
// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
// where the V value will be 27 or 28 for legacy reasons.
//
// The key used to calculate the signature is decrypted with the given password.
//
// https://github.com/ethereum/go-ethereum/wiki/Management-APIs#personal_sign
func (y *PrivateAccountApi) Sign(ctx context.Context, data hexutil.Bytes, addr common.Address, passwd string) (hexutil.Bytes, error) {
	// Look up the wallet containing the requested signer
	account, found := y.c.accountManager.Find(accounts.Account{Address: addr}.Address)
	if !found {
		return nil, accounts.ErrUnknownAccount
	}
	// Assemble sign the data with the wallet
	signature, err := y.c.accountManager.SignHashWithPassphrase(*account, passwd, signHash(data))
	if err != nil {
		logging.Warn("Failed data sign attempt", "address", addr, "err", err)
		return nil, err
	}
	signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
	return signature, nil
}

// EcRecover returns the address for the account that was used to create the signature.
// Note, this function is compatible with you_sign and personal_sign. As such it recovers
// the address of:
// hash = keccak256("\x19YOUChain Signed Message:\n"${message length}${message})
// addr = ecrecover(hash, signature)
//
// Note, the signature must conform to the secp256k1 curve R, S and V values, where
// the V value must be 27 or 28 for legacy reasons.
//
func (y *PrivateAccountApi) EcRecover(ctx context.Context, data, sig hexutil.Bytes) (common.Address, error) {
	if len(sig) != 65 {
		return common.Address{}, fmt.Errorf("signature must be 65 bytes long")
	}
	if sig[64] != 27 && sig[64] != 28 {
		return common.Address{}, fmt.Errorf("invalid Ethereum signature (V is not 27 or 28)")
	}
	sig[64] -= 27 // Transform yellow paper V from 27/28 to 0/1

	rpk, err := crypto.SigToPub(signHash(data), sig)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*rpk), nil
}

type ValAccountResult struct {
	Address    common.Address `json:"address"`
	MainPubKey hexutil.Bytes  `json:"mainPubKey"` //compressed consensus public key
	BlsPubKey  hexutil.Bytes  `json:"blsPubKey"`  //compressed bls public key
}

//NewValKey generates a new validator key that includes an ecdsa key and a bls key.
//the returned object includes an address and the compressed ecdsa public key (cons_cpk) and bls public key (bls_cpk)
func (y *PrivateAccountApi) NewValKey(password string) (*ValAccountResult, error) {
	va, err := y.c.accountManager.NewValKey(password)
	if err != nil {
		return nil, err
	}
	return &ValAccountResult{Address: va.Address, MainPubKey: va.MainPubKey, BlsPubKey: va.BlsPubKey}, nil
}

//UseValKey will unlock and set the validator key to consensus engine.
//If keep is true, then will store that validator key with plaintext, BE CAUTIOUS!
//Will only keep at most one validator key.
func (y *PrivateAccountApi) UseValKey(addr common.Address, password string, keep bool) error {
	return y.c.youChain.UseValKey(addr, password, keep)
}

//ExportValKey exports a validator key in a key json format, which is encrypted by the newPwd.
func (y *PrivateAccountApi) ExportValKey(addr common.Address, pwd, newPwd string) (keyJSON hexutil.Bytes, err error) {
	return y.c.accountManager.ExportValKey(addr, pwd, newPwd)
}

//ImportValKey imports and stores a validator key that is encrypted by pwd, and will re-encrypt by newPwd
func (y *PrivateAccountApi) ImportValKey(keyJSON hexutil.Bytes, pwd, newPwd string) (*ValAccountResult, error) {
	va, err := y.c.accountManager.ImportValKey(keyJSON, pwd, newPwd)
	if err != nil {
		return nil, err
	}
	return &ValAccountResult{Address: va.Address, MainPubKey: va.MainPubKey, BlsPubKey: va.BlsPubKey}, nil
}

//DelValKey will both try removing all unlocked validator keys and delete the specific key.
func (y *PrivateAccountApi) DelValKey(addr common.Address, pwd string) error {
	return y.c.accountManager.DelValKey(addr, pwd)
}

//LockValKey will remove all unlocked validator keys. It will not affect the currently used key in consensus engine
func (y *PrivateAccountApi) LockValKey() error {
	return y.c.accountManager.LockValKey()
}
