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
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/p2p/enode"
)

type BlacklistEventType string

const (
	BlacklistEventAddPeer    BlacklistEventType = "add"
	BlacklistEventRemovePeer BlacklistEventType = "remove"
	BlacklistEventClearDB    BlacklistEventType = "clearDB"

	chanLen = 16

	// peers are isolated at intervals
	blockingTime = 24 * time.Hour
)

type BlacklistEvent struct {
	Type       BlacklistEventType
	Enode      *enode.Node
	Hash       common.Hash
	ReceivedAt time.Time
}

type BlacklistItem struct {
	IP         string    `json:"ip"`
	RUDP       int       `json:"port"`
	Enode      string    `json:"enode"`
	ReceivedAt time.Time `json:"time"`
}

type Blacklist struct {
	Version uint64
	items   map[common.Hash]BlacklistItem

	eventFeed event.Feed
	eventCh   chan *BlacklistEvent

	doRefreshCh chan struct{}

	sync.RWMutex
	sync.WaitGroup

	localCtx context.Context
	doCancel context.CancelFunc

	db *blacklistDB

	running bool
}

func NewBlacklist(dbPath string) (*Blacklist, error) {
	logging.Info("init blacklist", "db path", dbPath)
	db, err := OpenDB(dbPath)
	if err != nil {
		logging.Error("open blacklist db failed", "db path", dbPath)
		return nil, err
	}

	bl := &Blacklist{
		eventCh:     make(chan *BlacklistEvent, chanLen),
		doRefreshCh: make(chan struct{}, 1), // one buffer is enough to signal the db refreshing
		running:     false,
		db:          db,
	}

	version, err := db.GetVersion()
	if err != nil {
		logging.Error("initBlacklist get Version failed", "err", err)
		return nil, err
	}

	bl.Version = version
	if version > 0 {
		items, err := db.GetBlacklist()
		if err != nil {
			logging.Error("initBlacklist get blacklist failed", "err", err)
			return nil, err
		}
		bl.items = items
	} else {
		bl.items = make(map[common.Hash]BlacklistItem)
	}

	ctx, doCancel := context.WithCancel(context.Background())
	bl.doCancel = doCancel
	bl.localCtx = ctx
	bl.Add(2)
	go bl.Start()
	go bl.doRefreshDBLoop()

	return bl, nil
}

func (bl *Blacklist) Close() (err error) {
	bl.doCancel()
	//shutdown event receive
	close(bl.eventCh)

	//wait pending
	bl.Wait()

	//stop db
	bl.items = nil
	err = bl.db.Close()

	bl.running = false

	//finally close do refresh chan
	close(bl.doRefreshCh)

	return err
}

func (bl *Blacklist) sendEvent(evt *BlacklistEvent) {
	bl.eventFeed.Send(evt)
}

func (bl *Blacklist) Start() {
	defer bl.doCancel()
	defer bl.Done()
	defer func() { bl.running = false }()

	bl.running = true

	sub := bl.eventFeed.Subscribe(bl.eventCh)
	defer sub.Unsubscribe()

	for {
		select {
		case <-bl.localCtx.Done():
			logging.Info("blacklist quit")
			return
		case <-sub.Err():
			logging.Error("Subscribe closed")
			return

		case subEvent, ok := <-bl.eventCh:
			if !ok {
				logging.Error("blacklist quit", "get event from chan", "chan was closed")
				return
			}

			switch subEvent.Type {
			case BlacklistEventRemovePeer:
				bl.Lock()
				if item, ok := bl.items[subEvent.Hash]; ok {
					delete(bl.items, subEvent.Hash)
					atomic.AddUint64(&bl.Version, 1)
					logging.Info("Remove expired elements", "received time", item.ReceivedAt, "remove time", subEvent.ReceivedAt, "remaining", len(bl.items), "Version", fmt.Sprintf("%d -> %d", bl.Version-1, bl.Version), "peer", item.Enode)
				}
				bl.Unlock()

				bl.signalDbRefresh()

			case BlacklistEventClearDB:
				bl.Lock()
				bl.items = make(map[common.Hash]BlacklistItem)
				atomic.AddUint64(&bl.Version, 1)
				logging.Info("clear blacklist db", "received time", subEvent.ReceivedAt)
				bl.Unlock()

				bl.signalDbRefresh()

			case BlacklistEventAddPeer:
				ip := subEvent.Enode.IP().String()
				port := subEvent.Enode.RUDP()
				addr := bytes.NewBufferString(fmt.Sprintf("%s:%d", ip, port))
				hash := crypto.Keccak256Hash(addr.Bytes())
				bl.Lock()
				if item, ok := bl.items[hash]; ok {
					item.ReceivedAt = subEvent.ReceivedAt
					logging.Info("peer has been added", "received time", item.ReceivedAt, "peer", item.Enode)
				} else {

					item := BlacklistItem{
						IP:         ip,
						RUDP:       port,
						Enode:      subEvent.Enode.String(),
						ReceivedAt: subEvent.ReceivedAt,
					}
					bl.items[hash] = item
					logging.Info("Successfully joined the peer into the blacklist", "received time", item.ReceivedAt, "peer addr", addr, "Version", fmt.Sprintf("%d -> %d", bl.Version-1, bl.Version), "peer", item.Enode)
				}
				atomic.AddUint64(&bl.Version, 1)
				bl.Unlock()

				bl.signalDbRefresh()
			}
		}
	}
}

func (bl *Blacklist) signalDbRefresh() {
	select {
	case bl.doRefreshCh <- struct{}{}:
	default:
	}
}

func (bl *Blacklist) doRefreshDBLoop() {
	defer bl.doCancel()
	defer bl.Done()
	defer func() { bl.running = false }()

	for {
		select {
		case <-bl.localCtx.Done():
			return
		case _, ok := <-bl.doRefreshCh:
			if ok {
				bl.doRefreshDB()
			}
		}
	}
}

func (bl *Blacklist) doRefreshDB() {
	version, err := bl.db.GetVersion()
	if err != nil {
		logging.Error("refresh to db failed", "get version err", err)
	} else {
		bl.RLock()
		if bl.Version > version {
			currVersion := bl.Version
			itemsBlob, err := bl.db.MarshalItems(bl.items)
			bl.RUnlock()
			if err != nil {
				logging.Error("MarshalItems failed", "err", err)
				return
			}
			err = bl.db.UpdateBlacklist(currVersion, itemsBlob)
			if err != nil {
				logging.Error("UpdateBlacklist failed", "err", err)
			}
		} else {
			bl.RUnlock()
		}
	}
}

func (bl *Blacklist) Check(hash common.Hash) (bool, error) {
	if !bl.running {
		return false, errors.New("blacklist not running")
	}

	remove := false
	defer func() {
		if remove {
			logging.Info("The peer expires and is removed from the blacklist")
			bl.sendEvent(&BlacklistEvent{
				Type:       BlacklistEventRemovePeer,
				Hash:       hash,
				ReceivedAt: time.Now(),
			})
		}
	}()

	bl.RLock()
	defer bl.RUnlock()

	if item, ok := bl.items[hash]; ok {
		now := time.Now()
		if !now.After(item.ReceivedAt.Add(blockingTime)) {
			return true, nil
		} else {
			remove = true
		}
	}
	return false, nil
}
