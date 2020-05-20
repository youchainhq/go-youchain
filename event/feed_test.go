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

package event

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type AE struct {
	N time.Time
}

func TestFeed_Subscribe(t *testing.T) {
	feed := &Feed{}
	c := make(chan AE)
	b := make(chan AE)
	feed.Subscribe(c)
	feed.Subscribe(b)
	done := sync.WaitGroup{}
	quit := make(chan struct{})

	got := 0
	done.Add(1)
	go func() {
		defer done.Done()
		for {
			select {
			case e := <-c:
				fmt.Println("from c", e)
				got++
			case e := <-b:
				fmt.Println("from b", e)
				got++
			case <-quit:
				return
			default:
			}
			time.Sleep(1 * time.Millisecond)
		}
	}()

	feed.Send(AE{N: time.Now()})
	feed.Send(AE{N: time.Now()})
	feed.Send(AE{N: time.Now()})
	feed.Send(AE{N: time.Now()})
	feed.Send(AE{N: time.Now()})

	go func() {
		quit <- struct{}{}
	}()
	done.Wait()
	if got != 10 {
		t.Errorf("event missing. want:%d, got:%d", 10, got)
	}
}

func TestFeed(t *testing.T) {
	var feed Feed
	var done, subscribed sync.WaitGroup

	subscriber := func(i int) {
		defer done.Done()
		subchan := make(chan int)
		sub := feed.Subscribe(subchan)

		subscribed.Done()

		select {
		case v := <-subchan:
			if v != 1 {
				t.Errorf("%d: received value %d, want 1", i, v)
			}
		}
		sub.Unsubscribe()
	}

	done.Add(1)
	subscribed.Add(1)

	go subscriber(1)

	subscribed.Wait()

	feed.Send(1)

	done.Wait()
}
