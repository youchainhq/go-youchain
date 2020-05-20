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

package p2p

import (
	"encoding/binary"
	"encoding/json"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/storage"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/logging"
)

const (
	dbVersionKey   = "version"
	dbBlackListKey = "blacklist"
)

var (
	defaultVersion uint64 = 0
)

type blacklistDB struct {
	lvl  *leveldb.DB   // Interface to the database itself
	quit chan struct{} // Channel to signal the expiring thread to stop
}

// open blacklist database for storing blacklist infos
// If no path is given an in-memory, temporary database is constructed
func OpenDB(path string) (*blacklistDB, error) {
	if path == "" {
		return newMemoryDB()
	}
	return newPersistentDB(path)
}

func newMemoryDB() (*blacklistDB, error) {
	db, err := leveldb.Open(storage.NewMemStorage(), nil)
	if err != nil {
		return nil, err
	}

	currentVer := make([]byte, binary.MaxVarintLen64)
	currentVer = currentVer[:binary.PutUvarint(currentVer, defaultVersion)]

	_, err = db.Get([]byte(dbVersionKey), nil)
	switch err {
	case leveldb.ErrNotFound:
		if err := db.Put([]byte(dbVersionKey), currentVer, nil); err != nil {
			db.Close()
			return nil, err
		}
	case nil:
	}

	return &blacklistDB{lvl: db, quit: make(chan struct{})}, nil
}

func newPersistentDB(path string) (*blacklistDB, error) {
	opts := &opt.Options{OpenFilesCacheCapacity: 5}
	db, err := leveldb.OpenFile(path, opts)
	if _, iscorrupted := err.(*errors.ErrCorrupted); iscorrupted {
		db, err = leveldb.RecoverFile(path, nil)
	}
	if err != nil {
		return nil, err
	}

	currentVer := make([]byte, binary.MaxVarintLen64)
	currentVer = currentVer[:binary.PutUvarint(currentVer, defaultVersion)]

	_, err = db.Get([]byte(dbVersionKey), nil)
	switch err {
	case leveldb.ErrNotFound:
		if err := db.Put([]byte(dbVersionKey), currentVer, nil); err != nil {
			db.Close()
			return nil, err
		}
	case nil:
	}

	return &blacklistDB{lvl: db, quit: make(chan struct{})}, nil
}

func (db *blacklistDB) GetVersion() (uint64, error) {
	blob, err := db.lvl.Get([]byte(dbVersionKey), nil)
	if err != nil {
		logging.Error("GetVersion failed", "err", err)
		return 0, err
	}

	version, ok := binary.Uvarint(blob)
	if ok <= 0 {
		logging.Error("Failed to get data version")
		return 0, errors.New("Failed to get data version")
	}

	return version, nil
}

func (db *blacklistDB) GetBlacklist() (map[common.Hash]BlacklistItem, error) {
	blob, err := db.lvl.Get([]byte(dbBlackListKey), nil)
	if err != nil {
		logging.Error("GetBlacklist failed", "err", err)
		return nil, err
	}

	var items = make(map[common.Hash]BlacklistItem)

	if err := json.Unmarshal(blob, &items); err != nil {
		logging.Error("decode failed", "err", err)
		return nil, err
	}

	return items, err
}

func (db *blacklistDB) MarshalItems(items map[common.Hash]BlacklistItem) ([]byte, error) {
	return json.Marshal(items)
}

func (db *blacklistDB) UpdateBlacklist(version uint64, itemsBlob []byte) error {
	versionBlob := make([]byte, binary.MaxVarintLen64)
	versionBlob = versionBlob[:binary.PutUvarint(versionBlob, version)]

	batch := new(leveldb.Batch)
	batch.Put([]byte(dbVersionKey), versionBlob)
	batch.Put([]byte(dbBlackListKey), itemsBlob)
	return db.lvl.Write(batch, nil)
}

func (db *blacklistDB) Close() error {
	close(db.quit)
	return db.lvl.Close()
}
