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
	"testing"

	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/youdb"
)

func TestNewVoteDB(t *testing.T) {
	//path := filepath.Join("./testdata", "vote")
	//logging.Info("path", "path", path)
	//db, _ := youdb.NewLDBDatabase(path, 768, 256)

	db := youdb.NewMemDatabase()

	rawSk, _ := crypto.GenerateKey()
	v := NewVoteDB(db, rawSk)
	logging.Info("addr", "addr", v.addr)

	v.UpdateContext(big.NewInt(8), uint32(1))
	v.UpdateVoteData(Prevote, big.NewInt(2), uint32(1))
	v.UpdateVoteData(Prevote, big.NewInt(3), uint32(10))
	v.UpdateVoteData(Prevote, big.NewInt(4), uint32(1))
	v.UpdateVoteData(Prevote, big.NewInt(5), uint32(1))
	v.UpdateVoteData(Prevote, big.NewInt(6), uint32(1))
	v.UpdateVoteData(Prevote, big.NewInt(6), uint32(2))
	v.UpdateVoteData(Prevote, big.NewInt(6), uint32(3))
	v.UpdateVoteData(Prevote, big.NewInt(7), uint32(1))
	v.UpdateVoteData(Prevote, big.NewInt(6), uint32(1))
	v.Stop()

	//db2, _ := youdb.NewLDBDatabase(path, 768, 256)
	db2 := youdb.NewMemDatabase()
	v2 := NewVoteDB(db2, rawSk)
	logging.Info("addr", "addr", v2.addr)
}
