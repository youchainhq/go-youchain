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

import (
	"github.com/youchainhq/go-youchain/common"
)

var (
	// UconDigest represents a hash of "Ucon practical byzantine fault tolerance"
	// to identify whether the block is from Ucon consensus engine
	UConMixHash = common.HexToHash("0x87c71741b903194ab0eb0bd581d5c522f0328e979f3c1bf29f6068bd2797fdf8")
)

// UconFilteredHeader returns a filtered header which some information (like validators)
// are clean to fulfill the Ucon hash rules. It returns nil if the validator-data cannot be
// decoded/encoded by rlp.
func UconFilteredHeader(h *Header) *Header {
	newHeader := CopyHeader(h)
	newHeader.Validator = []byte{}
	newHeader.Signature = []byte{}
	newHeader.Certificate = []byte{}

	return newHeader
}
