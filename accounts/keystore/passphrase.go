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
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/youchainhq/go-youchain/common"
	"os"
	"sync"
)

type PassphraseKeyStore struct {
	keydir  string
	scryptN int
	scryptP int
	mu      sync.Mutex
}

func (p *PassphraseKeyStore) ScryptP() int {
	return p.scryptP
}

func (p *PassphraseKeyStore) ScryptN() int {
	return p.scryptN
}

func NewPassphraseKeyStore(keydir string, scryptN, scryptP int) (*PassphraseKeyStore, error) {
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

	return &PassphraseKeyStore{
		keydir:  keydir,
		scryptN: scryptN,
		scryptP: scryptP,
	}, nil
}

func (ks *PassphraseKeyStore) GetKey(addr common.Address, filename string, passphrase string) (*Key, error) {
	// Load the key from the keystore and decrypt its contents
	keyJson, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	key, err := DecryptKey(keyJson, passphrase)
	if err != nil {
		return nil, err
	}
	// Make sure we're really operating on the requested key (no swap attacks)
	if key.Address != addr {
		return nil, fmt.Errorf("key content mismatch: have account %x, want %x", key.Address, addr)
	}
	return key, nil
}

func (ks *PassphraseKeyStore) StoreKey(filename string, key *Key, passphrase string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	keyJson, err := EncryptKey(key, passphrase, ks.scryptN, ks.scryptP)
	if err != nil {
		return err
	}
	return writeKeyFile(filename, keyJson)
}

func (ks *PassphraseKeyStore) JoinPath(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(ks.keydir, filename)
}

func (ks *PassphraseKeyStore) GetPath(addr common.Address) string {
	return ks.JoinPath(keyFileName(addr))
}

func (ks *PassphraseKeyStore) ImportKey(key *Key, passphrase string) (string, error) {
	path := ks.JoinPath(keyFileName(key.Address))
	if err := ks.StoreKey(path, key, passphrase); err != nil {
		return "", err
	} else {
		return path, nil
	}
}
