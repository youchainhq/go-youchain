// Copyright 2015 The go-ethereum Authors
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

package vm

import (
	"math/big"

	"github.com/youchainhq/go-youchain/params"
)

// Gas costs
const (
	GasQuickStep   uint64 = 2
	GasFastestStep uint64 = 3
	GasFastStep    uint64 = 5
	GasMidStep     uint64 = 8
	GasSlowStep    uint64 = 10
	GasExtStep     uint64 = 20
)

// callGas returns the actual gas remaining for the call.
func callGas(availableGas, base uint64, specifiedGas *big.Int) (uint64, error) {
	if specifiedGas.BitLen() > 64 {
		return 0, errGasUintOverflow
	}
	specGas := specifiedGas.Uint64()
	if specGas == 0 {
		// the call for a " addr.transfer(v)"
		return params.CallStipend, nil
	} else if availableGas <= specGas {
		// This mainly means that the user did not specified gas for the call,
		// in this case, the specifiedGas will be `the last available gas`,
		// since we already deducted a constant call gas,
		// so `the current available gas` is surely less then `the last available gas`.
		//
		// In this case, actually return the 63/64 of available gas
		if base > availableGas {
			return 0, ErrOutOfGas
		}
		availableGas = availableGas - base
		gas := availableGas - availableGas/64
		return gas, nil
	}
	// none of the above, return the specified gas
	return specGas, nil
}
