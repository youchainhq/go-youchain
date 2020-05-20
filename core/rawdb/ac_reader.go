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
	"encoding/binary"
	"errors"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/youdb"
	"time"
)

var (
	chtPrefix       = []byte("chtRoot-") // chtPrefix + chtNum (uint64 big endian) -> trie root hash
	bloomTriePrefix = []byte("bltRoot-") // bloomTriePrefix + bloomTrieNum (uint64 big endian) -> trie root hash
)

// GetChtRoot reads the CHT root associated to the given section from the database
func GetChtRoot(db youdb.Reader, sectionIdx uint64, sectionHead common.Hash) common.Hash {
	var encNumber [8]byte
	binary.BigEndian.PutUint64(encNumber[:], sectionIdx)
	data, _ := db.Get(append(append(chtPrefix, encNumber[:]...), sectionHead.Bytes()...))
	//if err != nil {
	//	logging.Warn("GetChtRoot", "err", err, "section", sectionIdx, "head", sectionHead.String())
	//}
	return common.BytesToHash(data)
}

// StoreChtRoot writes the CHT root associated to the given section into the database
func StoreChtRoot(db youdb.Putter, sectionIdx uint64, sectionHead, root common.Hash) error {
	var encNumber [8]byte
	binary.BigEndian.PutUint64(encNumber[:], sectionIdx)
	return db.Put(append(append(chtPrefix, encNumber[:]...), sectionHead.Bytes()...), root.Bytes())
}

// GetBloomTrieRoot reads the BloomTrie root assoctiated to the given section from the database
func GetBloomTrieRoot(db youdb.Reader, sectionIdx uint64, sectionHead common.Hash) common.Hash {
	var encNumber [8]byte
	binary.BigEndian.PutUint64(encNumber[:], sectionIdx)
	data, _ := db.Get(append(append(bloomTriePrefix, encNumber[:]...), sectionHead.Bytes()...))
	//if err != nil {
	//	logging.Warn("GetBloomTrieRoot", "err", err, "section", sectionIdx, "head", sectionHead.String())
	//}
	return common.BytesToHash(data)
}

// StoreBloomTrieRoot writes the BloomTrie root assoctiated to the given section into the database
func StoreBloomTrieRoot(db youdb.Putter, sectionIdx uint64, sectionHead, root common.Hash) error {
	var encNumber [8]byte
	binary.BigEndian.PutUint64(encNumber[:], sectionIdx)
	return db.Put(append(append(bloomTriePrefix, encNumber[:]...), sectionHead.Bytes()...), root.Bytes())
}

var emptyHash = common.Hash{}

type acReader struct {
	db        youdb.Reader
	frequency uint64
}

func NewAcReader(db youdb.Reader) AcReader {
	r := acReader{
		db:        db,
		frequency: params.ACoCHTFrequency,
	}
	return &r
}

func (r *acReader) ReadAcNode(headNum uint64, parentHash common.Hash) (chtRoot, bltRoot []byte, err error) {
	if headNum == 0 {
		return
	}
	if (headNum % r.frequency) != 0 {
		return
	}

	section := (headNum / r.frequency) - 1
	defer func(start time.Time) {
		logging.Trace("ReadAcNode elapse:", "section", section, "duration", time.Since(start).String())
	}(time.Now())
	//
	chtRootH := GetChtRoot(r.db, section, parentHash)
	bltRootH := GetBloomTrieRoot(r.db, section, parentHash)
	isEmpty := func(root common.Hash) bool {
		return root == emptyHash
	}
	isbltEmpty, ischtEmpty := isEmpty(bltRootH), isEmpty(chtRootH)
	if isbltEmpty || ischtEmpty {
		logging.Debug("ReadAcNode first try failed.", "headNum", headNum, "chtRoot", chtRoot, "bltRoot", bltRoot)
		//retry until done or timeout, using a polling scheme for simplicity.
		tick := time.NewTicker(29 * time.Millisecond)
		after := time.After(3000 * time.Millisecond) //timeout

		doneOrTimeout := false
		for {
			select {
			case <-tick.C:
				if isbltEmpty {
					bltRootH = GetBloomTrieRoot(r.db, section, parentHash)
					isbltEmpty = isEmpty(bltRootH)
				}
				if ischtEmpty {
					chtRootH = GetChtRoot(r.db, section, parentHash)
					ischtEmpty = isEmpty(chtRootH)
				}
				if !(isbltEmpty || ischtEmpty) {
					doneOrTimeout = true
				}
			case <-after:
				missingStr := ""
				switch {
				case ischtEmpty && !isbltEmpty:
					missingStr = "chtRoot"
				case isbltEmpty && !ischtEmpty:
					missingStr = "bltRoot"
				default:
					missingStr = "chtRoot and bltRoot"
				}
				err = errors.New("can not get " + missingStr)
				doneOrTimeout = true
			}
			if doneOrTimeout {
				break
			}
		}
		tick.Stop()
	}
	if err == nil {
		// set the return value
		chtRoot = chtRootH.Bytes()
		bltRoot = bltRootH.Bytes()
	}
	return
}

func (r *acReader) ReadCHTRootWithWait(headNum uint64, parentHash common.Hash, timeout time.Duration) (chtRoot []byte, err error) {
	if headNum == 0 {
		return
	}
	if (headNum % r.frequency) != 0 {
		return
	}

	section := (headNum / r.frequency) - 1
	defer func(start time.Time) {
		logging.Trace("ReadCHTRootWithWait return", "section", section, "duration", time.Since(start).String(), "err", err)
	}(time.Now())
	//
	chtRootH := GetChtRoot(r.db, section, parentHash)
	isEmpty := func(root common.Hash) bool {
		return root == emptyHash
	}
	if isEmpty(chtRootH) {
		logging.Debug("ReadCHTRootWithWait first try failed.", "headNum", headNum)
		//retry until done or timeout, using a polling scheme for simplicity.
		tick := time.NewTicker(29 * time.Millisecond)
		after := time.After(timeout) //timeout

		doneOrTimeout := false
		for {
			select {
			case <-tick.C:
				chtRootH = GetChtRoot(r.db, section, parentHash)

				if !isEmpty(chtRootH) {
					doneOrTimeout = true
				}
			case <-after:
				err = errors.New("can not get chtRoot")
				doneOrTimeout = true
			}
			if doneOrTimeout {
				break
			}
		}
		tick.Stop()
	}
	if err == nil {
		// set the return value
		chtRoot = chtRootH.Bytes()
	}
	return
}
