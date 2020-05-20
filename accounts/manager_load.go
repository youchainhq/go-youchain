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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/youchainhq/go-youchain/accounts/keystore"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/crypto"
	"io/ioutil"
	"os"
	"strings"
)

func (manager *Manager) loadAccounts() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	files, _ := ioutil.ReadDir(manager.ks.JoinPath(""))
	var accounts []*Account
	for _, file := range files {
		acc, err := manager.loadKeyFile(file)
		if err != nil {
			// errors have been recorded
			fmt.Printf("error: %s\n", err.Error())
			continue
		}
		if strings.HasPrefix(file.Name(), uvPrefix) {
			key, err := manager.ks.GetKey(acc.Address, acc.Path, "")
			if err != nil || !key.IsValKey() {
				//remove uncorrected file
				os.Remove(acc.Path)
				continue
			}
			manager.unlockedValKey = key
		}
		accounts = append(accounts, acc)
	}
	manager.accounts = accounts
	return nil
}

func (manager *Manager) loadKeyFile(file os.FileInfo) (*Account, error) {
	path := manager.ks.JoinPath(file.Name())

	if file.IsDir() || strings.HasPrefix(file.Name(), ".") || strings.HasSuffix(file.Name(), "~") {
		return nil, errors.New("file need skip" + file.Name())
	}

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.New("failed to read the key file")
	}

	var (
		addressJson struct {
			Address string `json:"address"`
		}
	)

	account := Account{Path: path}
	err = json.Unmarshal(raw, &addressJson)
	if err != nil {
		return nil, errors.New("failed to parse the key file")
	}

	//todo verify address
	account.Address = common.HexToAddress(addressJson.Address)
	return &account, nil
}

// Update passphrase of account
func (manager *Manager) Update(account *Account, passphrase, newPassphrase string) error {
	key, err := manager.ks.GetKey(account.Address, account.Path, passphrase)
	if err != nil {
		return err
	}
	return manager.ks.StoreKey(account.Path, key, newPassphrase)
}

// ImportECDSA stores the given key into the key directory, encrypting it with the passphrase.
func (manager *Manager) ImportECDSA(priv *ecdsa.PrivateKey, passphrase string) (*Account, error) {
	account, err := manager.setKeyStore(priv, []byte(passphrase))
	if err != nil {
		return nil, err
	}
	manager.accounts = append(manager.accounts, account)
	return account, nil
}

// ExportECDSA export a private key
func (manager *Manager) ExportECDSA(a *Account, passphrase string) (string, error) {
	key, err := manager.ks.GetKey(a.Address, a.Path, passphrase)
	if err != nil {
		return "0x0", err
	}
	privateKey := hexutil.Encode(crypto.FromECDSA(key.PrivateKey))
	return privateKey, nil
}

// Import stores the given encrypted JSON key into the key directory.
func (manager *Manager) Import(keyJSON []byte, passphrase, newPassphrase string) (*Account, error) {
	key, err := keystore.DecryptKey(keyJSON, passphrase)
	if key != nil && key.PrivateKey != nil {
		defer keystore.ZeroKey(key.PrivateKey)
	}
	if err != nil {
		return &Account{}, err
	}
	path, err := manager.ks.ImportKey(key, newPassphrase)
	if err != nil {
		return &Account{}, err
	}
	acc := &Account{Address: key.Address, Path: path}
	manager.accounts = append(manager.accounts, acc)
	return acc, nil
}

// Export exports as a JSON key, encrypted with newPassphrase.
func (manager *Manager) Export(a *Account, passphrase, newPassphrase string) (keyJSON []byte, err error) {
	key, err := manager.ks.GetKey(a.Address, a.Path, passphrase)
	if err != nil {
		return nil, err
	}
	var N, P int
	if ks, ok := manager.ks.(*keystore.PassphraseKeyStore); ok {
		N, P = ks.ScryptN(), ks.ScryptP()
	} else {
		N, P = keystore.StandardScryptN, keystore.StandardScryptP
	}
	return keystore.EncryptKey(key, newPassphrase, N, P)
}
