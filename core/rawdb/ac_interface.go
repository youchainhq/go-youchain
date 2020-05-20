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

package rawdb

import (
	"github.com/youchainhq/go-youchain/common"
	"time"
)

//AcReader contains functions for the main consensus engine to read data about ACoCHT
type AcReader interface {
	//ReadAcNode gets the node data (chtRoot, bltRoot) if headNum is multiples of params.ACoCHTFrequency
	ReadAcNode(headNum uint64, parentHash common.Hash) (chtRoot, bltRoot []byte, err error)
	//ReadCHTRootWithWait gets the chtRoot from database if headNum is multiples of params.ACoCHTFrequency, with a timeout.
	ReadCHTRootWithWait(headNum uint64, parentHash common.Hash, timeout time.Duration) (chtRoot []byte, err error)
}
