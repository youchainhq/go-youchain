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

package ucon

import (
	"math/big"

	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/params"
)

type LookBackMgr interface {
	CurrentCaravelParams() *params.CaravelParams

	//GetLookBackBlockNumber return the stake-look-back block number for the specific block number.
	//GetLookBackBlockNumber(cp *params.CaravelParams, num *big.Int, lbType params.LookBackType) *big.Int

	//GetLookBackBlockHash(cp *params.CaravelParams, num *big.Int, lbType params.LookBackType) (common.Hash, error)

	// GetLookBackVldReader gets canonical look back validator reader
	GetLookBackVldReader(cp *params.CaravelParams, num *big.Int, lbType params.LookBackType) (state.ValidatorReader, error)
}
