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
	"github.com/youchainhq/go-youchain/p2p"
	"github.com/youchainhq/go-youchain/p2p/enode"
)

type PrivateAdminApi struct {
	node *Node
}

func NewPrivateAdminApi(node *Node) *PrivateAdminApi {
	return &PrivateAdminApi{node}
}

// AddPeer requests connecting to a remote node, and also maintaining the new
// connection at all times, even reconnecting if it is lost.
func (api *PrivateAdminApi) AddPeer(url string) (bool, error) {
	// Make sure the server is running, fail otherwise
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	// Try to add the url as a static peer and return
	node, err := enode.ParseV4(url)
	if err != nil {
		return false, fmt.Errorf("invalid enode: %v", err)
	}
	server.AddPeer(node)
	return true, nil
}

// RemovePeer disconnects from a remote node if the connection exists
func (api *PrivateAdminApi) RemovePeer(url string) (bool, error) {
	// Make sure the server is running, fail otherwise
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	// Try to remove the url as a static peer and return
	node, err := enode.ParseV4(url)
	if err != nil {
		return false, fmt.Errorf("invalid enode: %v", err)
	}
	server.RemovePeer(node)
	return true, nil
}

// StopRPC terminates an already running HTTP RPC API endpoint.
func (api *PrivateAdminApi) StopRPC() (bool, error) {
	api.node.lock.Lock()
	defer api.node.lock.Unlock()

	if api.node.httpHandler == nil {
		return false, fmt.Errorf("HTTP RPC not running")
	}
	api.node.stopHTTP()
	return true, nil
}

// StopRPC terminates an already running HTTP RPC API endpoint.
func (api *PrivateAdminApi) StartRPC(host *string, port *int, cors *string, apis *string, vhosts *string) (bool, error) {
	return api.node.StartHTTP(host, port, cors, apis, vhosts)
}

// StartWS starts the websocket RPC API server.
func (api *PrivateAdminApi) StartWS(host *string, port *int, allowedOrigins *string, apis *string) (bool, error) {
	return api.node.StartWS(host, port, allowedOrigins, apis)
}

// StopRPC terminates an already running HTTP RPC API endpoint.
func (api *PrivateAdminApi) StopWS() (bool, error) {
	return api.node.StopWS()
}

type RPCBlacklistItem struct {
	Count     int
	ItemsInfo []p2p.BlacklistItem
}

func (api *PrivateAdminApi) Blacklist() RPCBlacklistItem {
	items := RPCBlacklistItem{}
	list := api.node.GetP2pServer().GetBlacklist()

	items.Count = len(list)
	items.ItemsInfo = list

	return items
}

func (api *PrivateAdminApi) ClearBlacklistDB() {
	api.node.GetP2pServer().ClearBlacklistDB()
}

func (api *PrivateAdminApi) RemovePeerFromBlacklist(ip string, rudpPort int) bool {
	return api.node.GetP2pServer().RemovePeerFromBlacklist(ip, rudpPort)
}

type PublicAdminApi struct {
	node *Node
}

func NewPublicAdminApi(node *Node) *PublicAdminApi {
	return &PublicAdminApi{node}
}

// Peers retrieves all the information we know about each individual peer at the
// protocol granularity.
func (api *PublicAdminApi) Peers() ([]*p2p.PeerInfo, error) {
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}
	return server.PeersInfo(), nil
}

// NodeInfo retrieves all the information we know about the host node at the
// protocol granularity.
func (api *PublicAdminApi) NodeInfo() (*p2p.NodeInfo, error) {
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}
	return server.NodeInfo(), nil
}
