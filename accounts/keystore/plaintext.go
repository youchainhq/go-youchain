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

package keystore

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/pborman/uuid"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
)

type PlaintextKeyStore struct {
	keydir  string
	scryptN int
	scryptP int
	mu      sync.Mutex
}

func NewPlaintextKeyStore(keydir string, scryptN, scryptP int) (*PlaintextKeyStore, error) {
	if keydir == "" {
		var err error
		keydir, err = ioutil.TempDir("", "youstore")
		if err != nil {
			return nil, err
		}
	}

	if err := os.MkdirAll(keydir, 0700); err != nil {
		return nil, err
	}

	return &PlaintextKeyStore{
		keydir:  keydir,
		scryptN: scryptN,
		scryptP: scryptP,
	}, nil
}

func (ks *PlaintextKeyStore) GetKey(addr common.Address, filename string, passphrase string) (*Key, error) {
	// Load the key from the keystore and decrypt its contents
	keyJson, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()
	var plainKey PlainKeyJSON
	if err := json.Unmarshal(keyJson, &plainKey); err != nil {
		return nil, err
	}
	privateKey, err := crypto.HexToECDSA(plainKey.PrivateKey)
	storedAddress := crypto.PubkeyToAddress(privateKey.PublicKey)

	// Make sure we're really operating on the requested key (no swap attacks)
	if plainKey.Address != storedAddress.String() {
		return nil, fmt.Errorf("key content mismatch: have account %x, want %x", plainKey.Address, storedAddress)
	}

	return &Key{
		Id:         uuid.UUID(plainKey.Id),
		Address:    crypto.PubkeyToAddress(privateKey.PublicKey),
		PrivateKey: privateKey,
	}, nil
}

func (ks *PlaintextKeyStore) StoreKey(filename string, key *Key, passphrase string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	var plainKey PlainKeyJSON
	plainKey.Id = key.Id.String()
	plainKey.Address = key.Address.String()
	plainKey.PrivateKey = hex.EncodeToString(crypto.FromECDSA(key.PrivateKey))
	keyJson, err := json.Marshal(plainKey)
	if err != nil {
		return err
	}
	return writeKeyFile(filename, keyJson)
}

func (ks *PlaintextKeyStore) ImportKey(key *Key, passphrase string) (string, error) {
	path := ks.JoinPath(keyFileName(key.Address))
	if err := ks.StoreKey(path, key, passphrase); err != nil {
		return "", err
	} else {
		return path, nil
	}
}

func (ks *PlaintextKeyStore) JoinPath(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(ks.keydir, filename)
}

func (ks *PlaintextKeyStore) GetPath(addr common.Address) string {
	return ks.JoinPath(keyFileName(addr))
}
