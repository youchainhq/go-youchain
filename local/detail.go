/*
 * Copyright 2020 YOUCHAIN FOUNDATION LTD.
 * This file is part of the go-youchain library.
 *
 * The go-youchain library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The go-youchain library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the go-youchain library. If not, see <http://www.gnu.org/licenses/>.
 */

package local

import (
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/rlp"
	"github.com/youchainhq/go-youchain/youdb"
)

const keyLen int = 34

var (
	_ DetailDB = &detailDB{}

	blockDetailPrefix = []byte{'b', 'd'}
)

type DetailDB interface {
	NewRecorder() DetailRecorder
	WriteDetail(d *Detail)
	ReadDetail(blockHash common.Hash) *Detail
	Close()
}

func NewDetailDB(db youdb.Database, isWatch bool) DetailDB {
	if isWatch && db == nil {
		panic("should provide a database for detail records")
	}
	return &detailDB{
		db:      db,
		isWatch: isWatch,
	}
}

func FakeDetailDB() DetailDB {
	return &detailDB{}
}

func blockDetailKey(blockHash common.Hash) []byte {
	key := make([]byte, keyLen)
	copy(key[:2], blockDetailPrefix)
	copy(key[2:], blockHash.Bytes())
	return key
}

type detailDB struct {
	db      youdb.Database
	isWatch bool
}

func (db *detailDB) NewRecorder() DetailRecorder {
	return &recorder{
		watch: db.isWatch,
	}
}

func (db *detailDB) WriteDetail(d *Detail) {
	if !db.isWatch ||
		d == nil ||
		(len(d.Rewards) == 0 && len(d.InnerTxs) == 0) {
		return
	}
	rlpData, err := rlp.EncodeToBytes(d)
	if err != nil {
		logging.Crit("SHOULD NOT HAPPEN! rlp encode detail failed", "err", err)
	}
	if err = db.db.Put(blockDetailKey(d.BlockHash), rlpData); err != nil {
		logging.Error("write detail to db failed", "err", err)
	}
}

func (db *detailDB) ReadDetail(blockHash common.Hash) *Detail {
	if db.db == nil {
		return nil
	}

	data, err := db.db.Get(blockDetailKey(blockHash))
	if err != nil {
		logging.Error("read detail data failed", "err", err)
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	var dec Detail
	err = rlp.DecodeBytes(data, &dec)
	if err != nil {
		logging.Error("rlp decode failed", "err", err, "data", hexutil.Encode(data))
		return nil
	}
	return &dec
}

func (db *detailDB) Close() {
	if db.db == nil {
		return
	}
	db.isWatch = false
	db.db.Close()
}
