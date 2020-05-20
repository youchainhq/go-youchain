// Copyright 2018 The go-ethereum Authors
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

package rawdb

import (
	"encoding/binary"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/rlp"
)

// ReadDatabaseVersion retrieves the version number of the database.
func ReadDatabaseVersion(db DatabaseReader) int {
	var version int

	enc, _ := db.Get(databaseVerisionKey)
	rlp.DecodeBytes(enc, &version)

	return version
}

// WriteDatabaseVersion stores the version number of the database
func WriteDatabaseVersion(db DatabaseWriter, version int) {
	enc, _ := rlp.EncodeToBytes(version)
	if err := db.Put(databaseVerisionKey, enc); err != nil {
		logging.Crit("Failed to store the database version", "err", err)
	}
}

// ReadNetworkId retrieves the consensus settings based on the given genesis hash.
func ReadNetworkId(db DatabaseReader, hash common.Hash) (networkId uint64) {
	data, _ := db.Get(networkIdKey(hash))
	if len(data) == 8 {
		networkId = binary.BigEndian.Uint64(data)
	}
	return
}

// WriteNetworkId writes the networkId to the database.
func WriteNetworkId(db DatabaseWriter, hash common.Hash, networkId uint64) {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, networkId)
	if err := db.Put(networkIdKey(hash), data); err != nil {
		logging.Crit("Failed to store networkId", "err", err)
	}
}
