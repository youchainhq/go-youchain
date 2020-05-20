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
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/logging"
	"time"
)

func (manager *Manager) expire(address common.Address, u *unlocked, timeout time.Duration) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-u.abort:
		// just quit
	case <-t.C:
		manager.mu.Lock()
		// only drop if it's still the same key instance that dropLater
		// was launched with. we can check that using pointer equality
		// because the map stores a new pointer every time the key is
		// unlocked.
		if manager.unlocked[address] == u {
			keystore.ZeroKey(u.PrivateKey)
			delete(manager.unlocked, address)
		}
		manager.mu.Unlock()
		logging.Info("unlocked", "num", len(manager.unlocked), "unlock expire", address.String())
	}
}

func (manager *Manager) Lock(address common.Address) error {
	manager.mu.Lock()
	if unl, found := manager.unlocked[address]; found {
		manager.mu.Unlock() //must unlock before manager.expire since func expire will lock again
		manager.expire(address, unl, 0*time.Nanosecond)
	} else {
		manager.mu.Unlock()
	}
	return nil
}

func (manager *Manager) Unlocked() map[common.Address]*unlocked {
	return manager.unlocked
}

func (manager *Manager) Unlock(account *Account, passphrase string) error {
	return manager.TimedUnlock(account, passphrase, 0)
}

func (manager *Manager) TimedUnlock(account *Account, passphrase string, timeout time.Duration) error {
	key, err := manager.ks.GetKey(account.Address, account.Path, passphrase)
	if err != nil {
		return err
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()

	u, found := manager.unlocked[account.Address]
	if found {
		if u.abort == nil {
			// The address was unlocked indefinitely, so unlocking
			// it with account timeout would be confusing.
			keystore.ZeroKey(key.PrivateKey)
			return nil
		}
		// Terminate the expire goroutine and replace it below.
		close(u.abort)
	}

	if timeout > 0 {
		u = &unlocked{Key: key, abort: make(chan struct{})}
		go manager.expire(account.Address, u, timeout)
	} else {
		u = &unlocked{Key: key}
	}
	manager.unlocked[account.Address] = u
	return nil
}

func (manager *Manager) Status(account Account) (string, error) {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	if _, ok := manager.unlocked[account.Address]; ok {
		return "Unlocked", nil
	}
	return "Locked", nil
}
