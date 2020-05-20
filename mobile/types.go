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
	"github.com/youchainhq/go-youchain/accounts"
	"github.com/youchainhq/go-youchain/common"
)

type Account struct {
	account *accounts.Account
}

func (acc *Account) GetAddress() *Address {
	return &Address{acc.account.Address}
}

func (acc *Account) GetPath() string {
	return acc.account.Path
}

// Address represents the 20 byte address of an Ethereum account.
type Address struct {
	address common.Address
}

func (address Address) String() string {
	return address.address.String()
}

func NewAddress(address string) (*Address, error) {
	mixedAddr, err := common.NewMixedcaseAddressFromString(address)
	if err != nil {
		return nil, err
	}

	if !mixedAddr.ValidChecksum() {
		return nil, errors.New("invalid address")
	}

	return &Address{
		address: common.HexToAddress(address),
	}, nil
}

//{"jsonrpc":"2.0","id":2,"result":0}
type JsonRpcIntResponse struct {
	JsonRpc string `json:"jsonrpc"`
	Id      int64  `json:"id"`
	Result  string `json:"result"`
}
