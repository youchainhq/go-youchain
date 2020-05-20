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
	"fmt"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/p2p/enode"
	"net"
	"testing"
	"time"
)

var (
	testEnode = "enode://368184f4c26649437478fc1532717aaed80766a8a37ca50eb7e2ae3736b3f0a83852c78a3a5be57fa6ca20bfae3868dde7c835453207a38dae5c43ab6808df9e@47.98.53.228:19283?discport=19284&nat=2&nodetype=2"
)

func setupBlacklist() *Blacklist {
	bl, err := NewBlacklist("")
	if err != nil {
		panic(err)
	}
	return bl
}

func TestBlacklistInstance(t *testing.T) {
	bl := setupBlacklist()
	defer bl.Close()

	enodes := ParseNodes([]string{testEnode})
	peer := NewTestPeer(enodes[0], "test", nil)

	bl.sendEvent(&BlacklistEvent{
		Type:       BlacklistEventAddPeer,
		Enode:      peer.Node(),
		ReceivedAt: time.Now(),
	})

	//delay
	time.Sleep(2 * time.Second)
	bl.sendEvent(&BlacklistEvent{
		Type:       BlacklistEventAddPeer,
		Enode:      peer.Node(),
		ReceivedAt: time.Now(),
	})

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peer.Node().IP().String(), peer.Node().RUDP()))
	if err != nil {
		t.Fatal(err)
	}

	if CheckAddrInBlacklist(bl, addr) {
		t.Logf("peer is in the blacklist, peer: %s", peer.Node())
	} else {
		t.Logf("peer don`t in the blacklist, peer: %s", peer.Node())
	}

}

func TestPeerDueto(t *testing.T) {
	bl := setupBlacklist()
	defer bl.Close()

	enodeStr := "enode://368184f4c26649437478fc1532717aaed80766a8a37ca50eb7e2ae3736b3f0a83852c78a3a5be57fa6ca20bfae3868dde7c835453207a38dae5c43ab6808df9e@47.98.53.218:19283?discport=19284&nat=2&nodetype=2"
	enodes := ParseNodes([]string{enodeStr})
	peer := NewTestPeer(enodes[0], "test", nil)

	d, _ := time.ParseDuration("-24h")
	beforeTime := time.Now().Add(d)
	t.Log("d = ", beforeTime)

	bl.sendEvent(&BlacklistEvent{
		Type:       BlacklistEventAddPeer,
		Enode:      peer.Node(),
		ReceivedAt: beforeTime,
	})

	bl.sendEvent(&BlacklistEvent{
		Type:       BlacklistEventAddPeer,
		Enode:      peer.Node(),
		ReceivedAt: time.Now(),
	})

	time.Sleep(2 * time.Second)
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peer.Node().IP().String(), peer.Node().RUDP()))
	if err != nil {
		t.Fatal(err)
	}

	if CheckAddrInBlacklist(bl, addr) {
		t.Logf("peer is in the blacklist, peer: %s", peer.Node())
	} else {
		t.Logf("peer don`t in the blacklist, peer: %s", peer.Node())
	}

	bl.sendEvent(&BlacklistEvent{
		Type:       BlacklistEventAddPeer,
		Enode:      peer.Node(),
		ReceivedAt: time.Now(),
	})
}

func TestClearBlacklistDB(t *testing.T) {
	bl := setupBlacklist()
	defer bl.Close()

	enodes := ParseNodes([]string{testEnode})

	peer := NewTestPeer(enodes[0], "test", nil)
	err := AddPeerToBlacklist(bl, peer)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)
	ClearBlacklistDB(bl)

	time.Sleep(2 * time.Second)
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peer.Node().IP().String(), peer.Node().RUDP()))
	if err != nil {
		t.Fatal(err)
	}

	if CheckAddrInBlacklist(bl, addr) {
		t.Fatalf("peer is in the blacklist, peer: %s", peer.Node())
	} else {
		t.Logf("peer don`t in the blacklist, peer: %s", peer.Node())
	}
}

func TestRemovePeerOnBlacklist(t *testing.T) {
	bl := setupBlacklist()
	defer bl.Close()

	enodes := ParseNodes([]string{testEnode})

	peer := NewTestPeer(enodes[0], "test", nil)
	err := AddPeerToBlacklist(bl, peer)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", peer.Node().IP().String(), peer.Node().RUDP()))
	if err != nil {
		t.Fatal(err)
	}

	RemoveAddrFromBlacklist(bl, addr)
}

func TestBlacklistDB(t *testing.T) {
	bl := setupBlacklist()

	enodes := ParseNodes([]string{testEnode})
	go func() {
		peer := NewTestPeer(enodes[0], "test", nil)

		err := AddPeerToBlacklist(bl, peer)
		if err != nil {
			t.Fatal(err)
		}

		time.Sleep(5 * time.Second)
		err = bl.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	bl.Wait()
}

func ParseNodes(input []string) []*enode.Node {
	urlArr := input
	nodes := make([]*enode.Node, 0, len(urlArr))
	for _, url := range urlArr {
		node, err := enode.ParseV4(url)
		if err != nil {
			logging.Error("Bootstrap URL invalid", "enode", url, "err", err)
			continue
		}
		nodes = append(nodes, node)
	}

	return nodes
}

func NewTestPeer(node *enode.Node, name string, caps []Cap) *Peer {
	conn := &conn{session: nil, transport: nil, node: node, caps: caps, name: name}
	peer := newPeer(conn, nil)
	close(peer.closed) // ensures Disconnect doesn't block
	return peer
}
