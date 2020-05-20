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

package youapi

import (
	"github.com/youchainhq/go-youchain/rpc"
	"github.com/youchainhq/go-youchain/you/filters"
)

func GetAPIs(container *Container) []rpc.API {
	nonceLock := new(AddrLocker)
	return []rpc.API{
		{
			Namespace: "you",
			Service:   NewPublicMainApi(container, nonceLock),
			Public:    true,
		},
		{
			Namespace: "you",
			Service:   filters.NewPublicFilterApi(container, false),
			Public:    true,
		},
		{
			Namespace: "personal",
			Service:   NewPrivateAccountApi(container, nonceLock),
			Public:    false,
		},
		{
			Namespace: "txpool",
			Service:   NewPublicTxpoolApi(container),
			Public:    true,
		},
		{
			Namespace: "dev",
			Service:   NewPrivateDevApi(container),
			Public:    false,
		},
	}
}
