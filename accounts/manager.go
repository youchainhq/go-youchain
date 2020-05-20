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
	"github.com/pborman/uuid"
	"github.com/youchainhq/go-youchain/accounts/keystore"
	"github.com/youchainhq/go-youchain/bls"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"math/big"
	"os"
	"sync"
)

type Manager struct {
	ks             Storage
	mu             sync.RWMutex
	accounts       []*Account
	unlocked       map[common.Address]*unlocked // Currently unlocked account (decrypted private keys)
	unlockedValKey *keystore.Key
	blsMgr         bls.BlsManager
	signer         types.Signer
}

type unlocked struct {
	*keystore.Key
	abort chan struct{}
}

func NewManager(ks Storage, blockNumber *big.Int) (*Manager, error) {
	if ks == nil {
		return nil, errKeystoreNotErrUninitialized
	}
	man := &Manager{
		ks:       ks,
		accounts: []*Account{},
		unlocked: make(map[common.Address]*unlocked),
		signer:   types.MakeSigner(blockNumber),
		blsMgr:   bls.NewBlsManager(),
	}
	man.init()
	return man, nil
}

func (manager *Manager) init() {
	manager.loadAccounts()
}

func (manager *Manager) Accounts() []*Account {
	return manager.accounts
}

func (manager *Manager) NewAccount(passphrase []byte) (*Account, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}

	account, err := manager.setKeyStore(privateKey, passphrase)
	if err != nil {
		return nil, err
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.accounts = append(manager.accounts, account)
	return account, nil
}

// Delete deletes the key matched by account if the passphrase is correct.
// If the account contains no filename, the address must match a unique key.
func (manager *Manager) Delete(address common.Address, passphrase string) error {
	if account, found := manager.Find(address); found {
		// Decrypting the key isn't really necessary, but we do
		// it anyway to check the password and zero out the key
		// immediately afterwards.
		key, err := manager.ks.GetKey(account.Address, account.Path, passphrase)
		if key != nil {
			keystore.ZeroKey(key.PrivateKey)
		}
		if err != nil {
			return err
		}
		// The order is crucial here. The key is dropped from the
		// cache after the file is gone so that account reload happening in
		// between won't insert it into the cache again.
		err = os.Remove(account.Path)
		delete(manager.unlocked, account.Address)
		manager.removeAccount(account)
		return err
	} else {
		return errAccountNotFound
	}
}

func (manager *Manager) Contains(address common.Address) bool {
	for i := range manager.accounts {
		if manager.accounts[i].Address == address {
			return true
		}
	}
	return false
}

func (manager *Manager) Find(address common.Address) (*Account, bool) {
	for i := range manager.accounts {
		if manager.accounts[i].Address == address {
			return manager.accounts[i], true
		}
	}
	return nil, false
}

func (manager *Manager) setKeyStore(privateKey *ecdsa.PrivateKey, passphrase []byte) (*Account, error) {
	pub := privateKey.PublicKey
	addr := crypto.PubkeyToAddress(pub)

	key := &keystore.Key{
		Id:         uuid.NewUUID(),
		Address:    addr,
		PrivateKey: privateKey,
	}

	path := manager.ks.GetPath(addr)
	err := manager.ks.StoreKey(path, key, string(passphrase))
	if err != nil {
		return nil, err
	}
	return &Account{Address: addr, Path: path}, nil
}

func (manager *Manager) removeAccount(account *Account) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	accounts := manager.accounts
	for i := range manager.accounts {
		if manager.accounts[i].Address == account.Address {
			accounts = append(manager.accounts[:i], manager.accounts[i+1:]...)
		}
	}
	manager.accounts = accounts
}
