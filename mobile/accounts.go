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

package mobile

import (
	"errors"
	"fmt"
	"github.com/youchainhq/go-youchain/crypto"
	"time"
)

func (y *YouMobile) CreateAccount(passphrase string) (*Account, error) {
	account, err := y.accountManager.NewAccount([]byte(passphrase))
	if err != nil {
		return nil, err
	}
	return &Account{account}, nil
}

func (y *YouMobile) Find(address string) (*Account, error) {
	addr, err := NewAddress(address)
	if err != nil {
		return nil, err
	}

	if account, found := y.accountManager.Find(addr.address); found {
		return &Account{account: account}, nil
	} else {
		return nil, errors.New("account not found")
	}
}

// UpdateAccount changes the passphrase of an existing account.
func (y *YouMobile) UpdateAccount(account *Account, passphrase, newPassphrase string) error {
	return y.accountManager.Update(account.account, passphrase, newPassphrase)
}

// ImportECDSA stores the given key into the key directory, encrypting it with the passphrase.
func (y *YouMobile) ImportECDSAKey(key string, passphrase string) (*Account, error) {
	if key[:2] != "0x" {
		return nil, fmt.Errorf("invalid hex string, 0x required")
	}
	privateKey, err := crypto.HexToECDSA(key[2:])
	if err != nil {
		return nil, err
	}
	acc, err := y.accountManager.ImportECDSA(privateKey, passphrase)
	if err != nil {
		return nil, err
	}
	return &Account{acc}, nil
}

func (y *YouMobile) ExportECDSAKey(account *Account, passphrase string) (string, error) {
	return y.accountManager.ExportECDSA(account.account, passphrase)
}

func (y *YouMobile) ExportKeyJson(account *Account, passphrase, newPassphrase string) (string, error) {
	bs, err := y.accountManager.Export(account.account, passphrase, newPassphrase)
	if err != nil {
		return "", err
	}
	return string(bs), nil
}

func (y *YouMobile) ImportKeyJson(keyJson string, passphrase, newPassphrase string) (*Account, error) {
	acc, err := y.accountManager.Import([]byte(keyJson), passphrase, newPassphrase)
	if err != nil {
		return nil, err
	}
	return &Account{acc}, nil
}

// Unlock unlocks the given account indefinitely.
func (y *YouMobile) Unlock(account *Account, passphrase string) error {
	return y.accountManager.TimedUnlock(account.account, passphrase, 0)
}

// Lock removes the private key with the given address from memory.
func (y *YouMobile) Lock(address *Address) error {
	return y.accountManager.Lock(address.address)
}

// TimedUnlock unlocks the given account with the passphrase. The account stays
// unlocked for the duration of timeout (nanoseconds). A timeout of 0 unlocks the
// account until the program exits. The account must match a unique key file.
//
// If the account address is already unlocked for a duration, TimedUnlock extends or
// shortens the active unlock timeout. If the address was previously unlocked
// indefinitely the timeout is not altered.
func (y *YouMobile) TimedUnlock(account *Account, passphrase string, timeout int64) error {
	return y.accountManager.TimedUnlock(account.account, passphrase, time.Duration(timeout))
}
