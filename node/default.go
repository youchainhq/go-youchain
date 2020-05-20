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

package node

import (
	"github.com/youchainhq/go-youchain/p2p"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rpc"
)

func NewDefaultConfig() Config {
	c := &DefaultConfig
	return *c
}

var (
	DefaultConfig = Config{
		Name:      "YOUChain",
		DataDir:   "data",
		NetworkId: 1,
		nodeType:  params.FullNode,
		RPC:       rpc.NewDefaultConfig(),
		P2P:       p2p.NewDefaultConfig(),
	}
)
