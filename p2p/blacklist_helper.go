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
	"errors"
	"fmt"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"net"
	"time"
)

func RemoveFromBlacklist(blacklist *Blacklist, ip string, rudpPort int) bool {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, rudpPort))
	if err != nil {
		logging.Error("remove peer from blacklist failed", "err", err)
		return false
	}

	return RemoveAddrFromBlacklist(blacklist, addr)
}

func AddPeerToBlacklist(blacklist *Blacklist, peer *Peer) error {
	if peer == nil {
		return errors.New("peer cannot be null")
	}

	blacklist.sendEvent(&BlacklistEvent{
		Type:       BlacklistEventAddPeer,
		Enode:      peer.Node(),
		ReceivedAt: time.Now(),
	})

	return nil
}

func CheckAddrInBlacklist(bl *Blacklist, addr net.Addr) bool {
	if addr == nil {
		logging.Error("blacklist check, address is nil")
		return false
	}

	buf := bytes.NewBufferString(addr.String())
	hash := crypto.Keccak256Hash(buf.Bytes())
	result, err := bl.Check(hash)
	if err != nil {
		logging.Error("blacklist check failed", "err", err)
		return false
	}

	return result
}

func ClearBlacklistDB(blacklist *Blacklist) {
	blacklist.sendEvent(&BlacklistEvent{
		Type:       BlacklistEventClearDB,
		ReceivedAt: time.Now(),
	})
}

func GetBlacklist(blacklist *Blacklist) []BlacklistItem {
	blacklist.RLock()
	defer blacklist.RUnlock()

	var items []BlacklistItem
	for _, item := range blacklist.items {
		items = append(items, item)
	}

	return items
}

func RemoveAddrFromBlacklist(blacklist *Blacklist, addr net.Addr) bool {
	if addr == nil {
		logging.Error("Remove Peer On blacklist failed", "err", "peer addr is nil")
		return false
	}

	buf := bytes.NewBufferString(addr.String())
	hash := crypto.Keccak256Hash(buf.Bytes())
	blacklist.RLock()
	if _, ok := blacklist.items[hash]; !ok {
		blacklist.RUnlock()
		return false
	}
	blacklist.RUnlock()
	blacklist.sendEvent(&BlacklistEvent{
		Type:       BlacklistEventRemovePeer,
		Hash:       hash,
		ReceivedAt: time.Now(),
	})

	return true
}
