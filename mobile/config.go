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
	"github.com/youchainhq/go-youchain/accounts"
	"github.com/youchainhq/go-youchain/accounts/keystore"
	"path/filepath"
)

var (
	StandardScryptN = keystore.StandardScryptN
	StandardScryptP = keystore.StandardScryptP
	LightScryptN    = keystore.LightScryptN
	LightScryptP    = keystore.LightScryptP

	PassphraseKeyStore = 0
	PlaintextKeyStore  = 1
)

type Config struct {
	Endpoint string
	DataDir  string
	ScryptN  int
	ScryptP  int
	Keystore int
}

var defaultMobileConfig = &Config{
	ScryptN:  StandardScryptN,
	ScryptP:  StandardScryptP,
	Keystore: PassphraseKeyStore,
}

// NewConfig creates a new node option set, initialized to the default values.
func NewConfig() *Config {
	config := *defaultMobileConfig
	return &config
}

func (config *Config) initStorage() (accounts.Storage, error) {
	keyStoreDir := filepath.Join(config.DataDir, "keystore")
	switch config.Keystore {
	case PlaintextKeyStore:
		return keystore.NewPlaintextKeyStore(keyStoreDir, config.ScryptN, config.ScryptP)
	case PassphraseKeyStore:
		fallthrough
	default:
		return keystore.NewPassphraseKeyStore(keyStoreDir, config.ScryptN, config.ScryptP)
	}
}
