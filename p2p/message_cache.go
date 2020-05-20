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
	lru "github.com/hashicorp/golang-lru"
	"github.com/youchainhq/go-youchain/common"
	"sync"
)

var (
	_messageCacheInstance *messageCache = nil
	messageCacheOnce      sync.Once
)

const (
	messageCacheLen = 65535
)

func RegisterFilterCode(code uint64) {
	MessageCacheInstance().AddFilterCode(code)
}

func UnregisterFilterCode(code uint64) {
	MessageCacheInstance().RemoveFilterCode(code)
}

type messageCache struct {
	cache *lru.Cache
	sync.RWMutex
	filters struct {
		m map[uint64]bool
		sync.RWMutex
	}
}

func MessageCacheInstance() *messageCache {
	messageCacheOnce.Do(func() {
		if _messageCacheInstance == nil {
			_messageCacheInstance = &messageCache{}
			_messageCacheInstance.cache, _ = lru.New(messageCacheLen)
			_messageCacheInstance.filters.m = make(map[uint64]bool)
		}
	})

	return _messageCacheInstance
}

func (pc *messageCache) AddFilterCode(code uint64) {
	pc.filters.Lock()
	defer pc.filters.Unlock()

	if _, ok := pc.filters.m[code]; !ok {
		pc.filters.m[code] = false
	}
}

func (pc *messageCache) RemoveFilterCode(code uint64) {
	pc.filters.Lock()
	defer pc.filters.Unlock()

	if _, ok := pc.filters.m[code]; ok {
		delete(pc.filters.m, code)
	}
}

func (pc *messageCache) MatchFilterCode(code uint64) bool {
	pc.filters.RLock()
	defer pc.filters.RUnlock()
	_, ok := pc.filters.m[code]
	return ok
}

func (pc *messageCache) AddMsg(hash common.Hash) {
	pc.cache.Add(hash, nil)
}

func (pc *messageCache) Check(hash common.Hash) bool {
	_, ok := pc.cache.Get(hash)
	return ok
}
