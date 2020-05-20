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

package p2p

import (
	"errors"
	"github.com/multiformats/go-multiaddr"
)

const NodeIDBits = 512

// Error types
var (
	ErrPeerIsNotConnected = errors.New("peer is not connected")
)

type NodeStatus struct {
	NodeIp *NodeIP // net.IPNet相关的
	ID     []byte  // 64位，IP+子网掩码，确定主机位于哪个子网，未来分片用
	Config *Config // 相关的配置
	Hosts  []multiaddr.Multiaddr
}
