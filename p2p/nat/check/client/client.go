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

package main

import (
	"flag"
	"fmt"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/p2p/nat/check"
	"net"
	"time"
)

var (
	log        = logging.New("Main", "Nat Client")
	masterAddr = flag.String("master.addr", "27.159.122.55:45521", "master node IP address and Port")
	slaveAddr  = flag.String("slave.addr", "27.159.122.3:45523", "slave node IP address and Port")
	listenPort = flag.Int("port", 9283, "listen port")
)

func main() {
	flag.Parse()
	logging.GRoot().Verbosity(logging.LvlDebug)
	m, err := net.ResolveUDPAddr("udp", *masterAddr)
	if err != nil {
		log.Error("setupServer", "ResolveUDPAddr err", err)
		return
	}

	s, err := net.ResolveUDPAddr("udp", *slaveAddr)
	if err != nil {
		log.Error("setupServer", "ResolveUDPAddr err", err)
		return
	}

	key, err := check.GenerateKey()
	if key == nil {
		log.Error("generate private key failed", "err", err)
		return
	}

	log.Info("port ", "port", *listenPort)

	//client := check.NewNATClient(key, m, s)
	client := check.NewNATClientAssignPort(key, m, s, *listenPort)
	ntype := client.Discover()
	if ntype != nil {
		fmt.Println("nat type: ", ntype.String())
	}

	time.Sleep(5 * time.Minute)
}
