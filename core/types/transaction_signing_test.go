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

package types

import (
	"github.com/stretchr/testify/assert"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/params"
	"log"
	"math/big"
	"testing"
)

func init() {
	params.InitNetworkId(params.NetworkIdForTestCase)
}

func TestSign(t *testing.T) {
	signer := MakeSigner(nil)
	key, address := DefaultTestKey()
	tx := NewTransaction(0, common.Address{}, new(big.Int), 0, new(big.Int), nil)

	tx, err := SignTx(tx, signer, key)

	if err != nil {
		log.Fatalln(err)
	}

	addr, err := Sender(signer, tx)
	if err != nil {
		log.Fatalln(err)
	}

	assert.Equal(t, addr, address)
}
