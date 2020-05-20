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

package mobile

import (
	"fmt"
	"github.com/youchainhq/go-youchain/crypto"
	"sync/atomic"
	"time"
)

var testPrivateKeyHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"

type Task struct {
	Finished chan bool
}

func (w Task) Run(msg, sig []byte, times int) {
	for i := 0; i < times; i++ {
		_, err := crypto.Ecrecover(msg, sig)
		if err != nil {
			fmt.Println(err)
		}
	}

	w.Finished <- true
}

// Recover return cpu benchmark
func Recover(times int, thread int) (int, error) {
	key, _ := crypto.HexToECDSA(testPrivateKeyHex)
	msg := crypto.Keccak256([]byte("foo"))
	sig, err := crypto.Sign(msg, key)
	if err != nil {
		return 0, err
	}

	now := time.Now().UnixNano()

	finished := make(chan bool, thread)

	for i := 0; i < thread; i++ {
		task := Task{finished}
		go task.Run(msg, sig, times/thread)
	}

	counter := int32(0)
	for {
		select {
		case <-finished:
			if atomic.AddInt32(&counter, 1) == int32(thread) {
				goto ret
			}
		}
	}

ret:
	return int((time.Now().UnixNano() - now) / 1e6), nil
}
