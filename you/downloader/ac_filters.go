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

package downloader

import (
	"sync"
)

// acFilter用于Downloader中ACoCHT相关的业务与常规下载业务并行时，识别并投递ACoCHT相关数据到特定通道。
type acFilter struct {
	lock sync.RWMutex
	ps   map[string]bool
}

func newAcFilter() *acFilter {
	return &acFilter{
		ps: make(map[string]bool),
	}
}

func (f *acFilter) Add(pid string) (isOk bool) {
	f.lock.Lock()
	if _, exist := f.ps[pid]; !exist {
		f.ps[pid] = true
		isOk = true
	}
	f.lock.Unlock()
	return
}

func (f *acFilter) Exist(pid string) (isOk bool) {
	f.lock.RLock()
	_, isOk = f.ps[pid]
	f.lock.RUnlock()
	return
}

func (f *acFilter) Remove(pid string) (isOk bool) {
	f.lock.Lock()
	if _, exist := f.ps[pid]; exist {
		delete(f.ps, pid)
		isOk = true
	}
	f.lock.Unlock()
	return
}
