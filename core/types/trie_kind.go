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

package types

type TrieKind uint8

const (
	KindState TrieKind = iota
	KindValidator
	KindCht
	KindBlt
	KindStaking
)

func (k TrieKind) String() string {
	switch k {
	case KindState:
		return "state"
	case KindValidator:
		return "validator"
	case KindCht:
		return "cht"
	case KindBlt:
		return "blt"
	case KindStaking:
		return "staking"
	default:
		return "unknown"
	}
}
