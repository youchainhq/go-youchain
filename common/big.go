// Copyright 2014 The go-ethereum Authors
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

package common

import "math/big"

// Common big integers often used
// in case mis-use, always return new instance

func Big1() *big.Int {
	return big.NewInt(1)
}

func Big2() *big.Int {
	return big.NewInt(2)
}

func Big3() *big.Int {
	return big.NewInt(3)
}

func Big0() *big.Int {
	return big.NewInt(0)
}

func Big32() *big.Int {
	return big.NewInt(32)
}

func Big256() *big.Int {
	return big.NewInt(256)
}

func Big257() *big.Int {
	return big.NewInt(257)
}
