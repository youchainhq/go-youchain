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

package params

import "strconv"

const (
	DefaultIPCPath = "youchain.ipc"

	DefaultHTTPHost = "localhost" // Default host interface for the HTTP RPC server
	DefaultHTTPPort = 8283

	DefaultWSHost = "localhost" // Default host interface for the websocket RPC server
	DefaultWSPort = 8284

	DefaultP2PListenPort = 9283 // Default port for the P2P RUDP transport

	DefaultP2PDiscoverPort = 9284 // Default port for the P2P Discover transport

	DefaultPProfHost = "0.0.0.0" //port for PProf metrics
	DefaultPProfPort = 7283      //port for PProf metrics
)

type NodeType uint16

const (
	UnknownNodeType NodeType = iota
	ArchiveNode
	FullNode
	LightNode
	UltraLightNode
)

func ParseNodeType(text string) NodeType {
	switch text {
	case "archive", "Archive":
		return ArchiveNode
	case "full", "Full":
		return FullNode
	case "light", "Light":
		return LightNode
	case "ultralight", "UltraLight":
		return UltraLightNode
	default:
		return UnknownNodeType
	}
}

func (t NodeType) IsValid() bool {
	return t >= ArchiveNode && t <= UltraLightNode
}

func (t NodeType) String() string {
	switch t {
	case UnknownNodeType:
		return "unknown"
	case ArchiveNode:
		return "archive"
	case FullNode:
		return "full"
	case LightNode:
		return "light"
	case UltraLightNode:
		return "ultralight"
	default:
		return strconv.Itoa(int(t))
	}
}
