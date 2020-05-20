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
	"fmt"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/params"
)

// public api for youchain
type PublicNodeApi struct {
	node *Node
}

func NewPublicNodeApi(node *Node) *PublicNodeApi {
	return &PublicNodeApi{node}
}

// ClientVersion returns the node name
func (n *PublicNodeApi) ClientVersion() string {
	return n.node.GetP2pServer().Name
}

// Sha3 applies the ethereum sha3 implementation on the input.
// It assumes the input is hex encoded.
func (n *PublicNodeApi) Sha3(input hexutil.Bytes) hexutil.Bytes {
	return crypto.Keccak256(input)
}

// public api for net
type PublicNetApi struct {
	node *Node
}

func NewPublicNetApi(node *Node) *PublicNetApi {
	return &PublicNetApi{node}
}

func (p *PublicNetApi) Version() string {
	return fmt.Sprintf("%d", params.NetworkId())
}

// Listening returns an indication if the node is listening for network connections.
func (p *PublicNetApi) Listening() bool {
	return true // always listening
}

// PeerCount returns the number of connected peers
func (p *PublicNetApi) PeerCount() hexutil.Uint {
	return hexutil.Uint(p.node.server.PeerCount())
}
