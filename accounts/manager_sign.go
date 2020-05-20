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
	"github.com/youchainhq/go-youchain/accounts/keystore"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/crypto"
	"math/big"
)

// SignHash calculates a ECDSA signature for the given hash. The produced signature
// is in the [R || S || V] format where V is 0 or 1.
func (manager *Manager) SignHash(account Account, hash []byte) (signature []byte, err error) {
	// Look up the key to sign with and abort if it cannot be found
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	unlockedKey, found := manager.unlocked[account.Address]
	if !found {
		return nil, ErrLocked
	}
	// Sign the hash using plain ECDSA operations
	return crypto.Sign(hash, unlockedKey.PrivateKey)
}

// SignTx signs the given transaction with the requested account.
func (manager *Manager) SignTx(account Account, tx *types.Transaction) (*types.Transaction, error) {
	// Look up the key to sign with and abort if it cannot be found
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	unlockedKey, found := manager.unlocked[account.Address]
	if !found {
		return nil, ErrLocked
	}

	return types.SignTx(tx, manager.signer, unlockedKey.PrivateKey)
}

// SignHashWithPassphrase signs hash if the private key matching the given address
// can be decrypted with the given passphrase. The produced signature is in the
// [R || S || V] format where V is 0 or 1.
func (manager *Manager) SignHashWithPassphrase(account Account, passphrase string, hash []byte) (signature []byte, err error) {
	key, err := manager.ks.GetKey(account.Address, account.Path, passphrase)
	if err != nil {
		return nil, err
	}
	defer keystore.ZeroKey(key.PrivateKey)
	return crypto.Sign(hash, key.PrivateKey)
}

// SignTxWithPassphrase signs the transaction if the private key matching the
// given address can be decrypted with the given passphrase.
func (manager *Manager) SignTxWithPassphrase(account Account, passphrase string, tx *types.Transaction) (*types.Transaction, error) {
	key, err := manager.ks.GetKey(account.Address, account.Path, passphrase)
	if err != nil {
		return nil, err
	}
	defer keystore.ZeroKey(key.PrivateKey)
	return types.SignTx(tx, manager.signer, key.PrivateKey)
}

func (manager *Manager) SignTxWithKey(key string, tx *types.Transaction, networkId *big.Int) (*types.Transaction, error) {
	privateKey, err := crypto.ToECDSA([]byte(key))
	if err != nil {
		return nil, err
	}
	return types.SignTx(tx, manager.signer, privateKey)
}
