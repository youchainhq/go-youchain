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

package accounts

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/pborman/uuid"
	"github.com/youchainhq/go-youchain/accounts/keystore"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"io/ioutil"
	"os"
	"strings"
)

const uvPrefix = "uvk-"

//NewValKey generates a new validator key that includes an ecdsa key and a bls key.
func (manager *Manager) NewValKey(pwd string) (*ValAccount, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	blsSk, blsPk := manager.blsMgr.GenerateKey()

	account, err := manager.setValKeyStore(privateKey, blsSk.Compress().Bytes(), pwd)
	if err != nil {
		return nil, err
	}

	cpk := crypto.CompressPubkey(&privateKey.PublicKey)
	va := ValAccount{
		Account:    *account,
		MainPubKey: cpk,
		BlsPubKey:  blsPk.Compress().Bytes(),
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.accounts = append(manager.accounts, account)
	return &va, nil
}

//UseValKey will unlock and return the required validator key.
//If keep is true, then will store that validator key with plaintext, BE CAUTIOUS!
//Will only keep at most one validator key.
func (manager *Manager) UseValKey(addr common.Address, pwd string, keep bool) (*keystore.Key, error) {
	if manager.unlockedValKey != nil && manager.unlockedValKey.Address == addr {
		//return cloned key
		return manager.unlockedValKey.Clone(), nil
	}
	account, found := manager.Find(addr)
	if !found {
		return nil, ErrUnknownAccount
	}
	key, err := manager.ks.GetKey(account.Address, account.Path, pwd)
	if err != nil {
		return nil, err
	}
	if !key.IsValKey() {
		return nil, ErrNotValKey
	}
	if keep {
		err = manager.clearUvFiles()
		if err != nil {
			return nil, fmt.Errorf("can't clear old uvKeyFile: %v", err)
		}
		path := manager.ks.JoinPath(getUvFileName(addr))
		err := manager.ks.StoreKey(path, key, "")
		if err != nil {
			return nil, err
		}
		manager.unlockedValKey = key.Clone()
	}
	return key, nil
}

func (manager *Manager) GetUnlockedValKey() *keystore.Key {
	if manager.unlockedValKey != nil {
		//return cloned key
		return manager.unlockedValKey.Clone()
	}
	return nil
}

func (manager *Manager) ExportValKey(addr common.Address, pwd, newPwd string) (keyJSON []byte, err error) {
	a, found := manager.Find(addr)
	if !found {
		return nil, ErrUnknownAccount
	}
	key, err := manager.ks.GetKey(a.Address, a.Path, pwd)
	if err != nil {
		return nil, err
	}
	if !key.IsValKey() {
		return nil, ErrNotValKey
	}
	var N, P int
	if ks, ok := manager.ks.(*keystore.PassphraseKeyStore); ok {
		N, P = ks.ScryptN(), ks.ScryptP()
	} else {
		N, P = keystore.StandardScryptN, keystore.StandardScryptP
	}
	return keystore.EncryptKey(key, newPwd, N, P)
}

func (manager *Manager) ImportValKey(keyJSON []byte, pwd, newPwd string) (*ValAccount, error) {
	key, err := keystore.DecryptKey(keyJSON, pwd)
	if key != nil && key.PrivateKey != nil {
		defer keystore.ZeroKey(key.PrivateKey)
	}
	if err != nil {
		return nil, err
	}
	if !key.IsValKey() {
		return nil, ErrNotValKey
	}
	path, err := manager.ks.ImportKey(key, newPwd)
	if err != nil {
		return nil, err
	}
	acc := &Account{Address: key.Address, Path: path}
	manager.accounts = append(manager.accounts, acc)
	cpk := crypto.CompressPubkey(&key.PrivateKey.PublicKey)
	blsSk, err := manager.blsMgr.DecSecretKey(key.BlsKey)
	if err != nil {
		return nil, err
	}
	blsPk, _ := blsSk.PubKey()
	va := &ValAccount{
		Account:    *acc,
		MainPubKey: cpk,
		BlsPubKey:  blsPk.Compress().Bytes(),
	}

	return va, nil
}

//DelValKey will both try removing all unlocked validator keys and delete the specific key.
func (manager *Manager) DelValKey(addr common.Address, pwd string) error {
	//try both to lock and delete
	err1 := manager.LockValKey()
	err2 := manager.Delete(addr, pwd)
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return nil
}

func (manager *Manager) LockValKey() error {
	if manager.unlockedValKey != nil {
		keystore.ZeroKey(manager.unlockedValKey.PrivateKey)
		manager.unlockedValKey = nil
	}
	err := manager.clearUvFiles()
	if err != nil {
		return fmt.Errorf("can't clear old uvKeyFile: %v", err)
	}
	return nil
}

func (manager *Manager) setValKeyStore(privateKey *ecdsa.PrivateKey, blsSk []byte, pwd string) (*Account, error) {
	pub := privateKey.PublicKey
	addr := crypto.PubkeyToAddress(pub)

	key := &keystore.Key{
		Id:         uuid.NewUUID(),
		Address:    addr,
		PrivateKey: privateKey,
		BlsKey:     blsSk,
	}

	path := manager.ks.GetPath(addr)
	err := manager.ks.StoreKey(path, key, pwd)
	if err != nil {
		return nil, err
	}
	return &Account{Address: addr, Path: path}, nil
}

func (manager *Manager) clearUvFiles() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	files, _ := ioutil.ReadDir(manager.ks.JoinPath(""))
	for _, file := range files {
		if !file.IsDir() {
			if strings.HasPrefix(file.Name(), uvPrefix) {
				path := manager.ks.JoinPath(file.Name())
				zeros := make([]byte, file.Size())
				ioutil.WriteFile(path, zeros, file.Mode()) //nolint
				err := os.Remove(path)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func getUvFileName(addr common.Address) string {
	return fmt.Sprintf("%s%s", uvPrefix, hex.EncodeToString(addr[:]))
}
