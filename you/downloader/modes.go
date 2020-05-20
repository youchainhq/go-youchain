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

package downloader

import (
	"github.com/youchainhq/go-youchain/params"
)

// SyncMode represents the synchronisation mode of the downloader.
type SyncMode int

const (
	InvalidSync SyncMode = iota
	FullSync             // Synchronise the entire blockchain history from full blocks
	FastSync             // download latest state, full sync only at the chain head
	LightSync
	UltraLightSync
)

func (mode SyncMode) IsValid() bool {
	return mode >= FullSync && mode <= UltraLightSync
}

// String implements the stringer interface.
func (mode SyncMode) String() string {
	return ToString(mode)
}

func ToString(mode SyncMode) string {
	switch mode {
	case FullSync:
		return "full"
	case FastSync:
		return "fast"
	case LightSync:
		return "light"
	case UltraLightSync:
		return "ultralight"
	default:
		return "unknown"
	}
}

func ToSyncMode(node params.NodeType) SyncMode {
	return SyncMode(node)
}
