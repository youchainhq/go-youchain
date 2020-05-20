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

package rpc

import (
	"fmt"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"math/big"
)

type TestService struct {
	count int
}

type IntData struct {
	Value int
}

func (s *TestService) GetBigInt() (*hexutil.Big, error) {
	ttt := big.NewInt(1231223232323)
	ttt2 := (*hexutil.Big)(ttt)
	return ttt2, nil
}

func (s *TestService) GetBytes(name string, age int) ([]byte, error) {
	return []byte(fmt.Sprintf("bytes: %s", name)), nil
}

func (s *TestService) GetString() (string, error) {
	return "name:wjq", nil
}

func (s *TestService) NewAccount(arg *NoArgs) (ret map[string][]byte, err error) {
	ret = make(map[string][]byte)
	return
}

func (n *TestService) Profile(args *NoArgs) (ret map[string]string, err error) {
	return map[string]string{"name": "wjq", "age": "100"}, nil
}
