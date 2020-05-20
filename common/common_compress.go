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

package common

import "github.com/nanyan/golz4"

// Compress compresses the input byte slice using go-binding lz4 algorithm.
// caller MUST keep the length of the input data in order to decompress it later.
func Compress(data []byte) ([]byte, error) {
	out := make([]byte, lz4.CompressBound(data)) //pre-allocate memory
	outSize, err := lz4.Compress(data, out)
	return out[:outSize], err
}

// Decompress decompresses data with a known target size.
func Decompress(data []byte, target int) ([]byte, error) {
	out := make([]byte, target) //pre-allocate memory
	_, err := lz4.Uncompress(data, out)
	return out, err
}
