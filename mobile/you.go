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
	"encoding/json"
	"github.com/youchainhq/go-youchain/accounts"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/rpc"
	"runtime"
	"sync"
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

type YouMobile struct {
	config         *Config
	client         *rpc.Client
	accountManager accounts.AccountManager
	signer         *types.Signer
	mutex          sync.Mutex
}

func (y *YouMobile) AccountManager() accounts.AccountManager {
	return y.accountManager
}

func NewYouMobile(config *Config) (*YouMobile, error) {
	if config == nil {
		config = NewConfig()
	}

	storage, err := config.initStorage()
	if err != nil {
		return nil, err
	}

	accountManager, err := accounts.NewManager(storage, nil)
	if err != nil {
		return nil, err
	}

	youMobile := &YouMobile{
		config:         config,
		accountManager: accountManager,
	}
	return youMobile, nil
}

func (y *YouMobile) conn() error {
	client, err := rpc.Dial(y.config.Endpoint)
	if err != nil {
		return err
	}
	y.client = client
	return nil
}

func (y *YouMobile) Call(api string, params []byte) (string, error) {
	if y.client == nil {
		if err := y.conn(); err != nil {
			return "", err
		}
	}
	if params == nil {
		params = []byte(`[]`)
	}
	var reply string
	if err := y.client.Call(&reply, api, params); err != nil {
		return "", err
	} else {
		return reply, nil
	}
}

func buildParams(args ...interface{}) ([]byte, error) {
	return json.Marshal(args)
}
