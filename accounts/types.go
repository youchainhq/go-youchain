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

package accounts

import (
	"crypto/ecdsa"
	"github.com/youchainhq/go-youchain/accounts/keystore"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"math/big"
	"time"
)

type Storage interface {
	GetKey(addr common.Address, filename string, passphrase string) (*keystore.Key, error)
	StoreKey(filename string, key *keystore.Key, passphrase string) error
	ImportKey(key *keystore.Key, passphrase string) (string, error)
	JoinPath(filename string) string
	GetPath(addr common.Address) string
}

type Account struct {
	Address common.Address `json:"address"`
	Path    string         `json:"path"`
}

//ValAccount is a validator account, for convenient
type ValAccount struct {
	Account
	MainPubKey []byte //consensus compressed public key
	BlsPubKey  []byte //compressed bls public key
}

// Wallet represents a software or hardware wallet that might contain one or more
// accounts (derived from the same seed).
type Wallet interface {
	// Contains returns whether an account is part of this particular wallet or not.
	Contains(account Account) bool

	// SignTx requests the wallet to sign the given transaction.
	//
	// It looks up the account specified either solely via its address contained within,
	// or optionally with the aid of any location metadata from the embedded URL field.
	//
	// If the wallet requires additional authentication to sign the request (e.g.
	// a password to decrypt the account, or a PIN code to verify the transaction),
	// an AuthNeededError instance will be returned, containing infos for the user
	// about which fields or actions are needed. The user may retry by providing
	// the needed details via SignTxWithPassphrase, or by other means (e.g. unlock
	// the account in a keystore).
	SignTx(account Account, tx *types.Transaction, networkId *big.Int) (*types.Transaction, error)
}

type AccountManager interface {
	Accounts() []*Account
	NewAccount(passphrase []byte) (*Account, error)
	Delete(address common.Address, passphrase string) error
	Update(account *Account, passphrase, newPassphrase string) error
	Contains(address common.Address) bool
	Find(address common.Address) (*Account, bool)

	Lock(address common.Address) error
	Unlock(account *Account, passphrase string) error
	TimedUnlock(account *Account, passphrase string, timeout time.Duration) error
	Status(account Account) (string, error)

	ImportECDSA(priv *ecdsa.PrivateKey, passphrase string) (*Account, error)
	ExportECDSA(a *Account, passphrase string) (string, error)
	Import(keyJSON []byte, passphrase, newPassphrase string) (*Account, error)
	Export(a *Account, passphrase, newPassphrase string) (keyJSON []byte, err error)

	SignHash(account Account, hash []byte) (signature []byte, err error)
	SignTx(account Account, tx *types.Transaction) (*types.Transaction, error)
	SignHashWithPassphrase(account Account, passphrase string, hash []byte) (signature []byte, err error)
	SignTxWithPassphrase(account Account, passphrase string, tx *types.Transaction) (*types.Transaction, error)
	SignTxWithKey(key string, tx *types.Transaction, networkId *big.Int) (*types.Transaction, error)

	//NewValKey generates a new validator key that includes an ecdsa key and a bls key.
	NewValKey(pwd string) (*ValAccount, error)
	//UseValKey will unlock and return the required validator key.
	//If keep is true, then will store that validator key with plaintext, BE CAUTIOUS!
	//Will only keep at most one validator key.
	UseValKey(addr common.Address, pwd string, keep bool) (*keystore.Key, error)
	//GetUnlockedValKey gets the unlocked validator key
	GetUnlockedValKey() *keystore.Key
	//ExportValKey is like as Export, just do more check about validator key
	ExportValKey(addr common.Address, pwd, newPwd string) (keyJSON []byte, err error)
	ImportValKey(keyJSON []byte, pwd, newPwd string) (*ValAccount, error)
	//DelValKey will both try removing all unlocked validator keys and delete the specific key.
	DelValKey(addr common.Address, pwd string) error
	//LockValKey will remove all unlocked validator keys
	LockValKey() error
}
