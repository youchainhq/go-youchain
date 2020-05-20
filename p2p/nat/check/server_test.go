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

package check

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/youchainhq/go-youchain/crypto"
	"net"
	"testing"
	"time"
)

var (
	master = ":23456"
	slave  = ":23457"
)

func getPrivKey() *ecdsa.PrivateKey {
	key, err := crypto.GenerateKey()
	if err != nil {
		log.Crit(fmt.Sprintf("Failed to generate node key: %v", err))
		return nil
	}

	return key
}

func Test_Server(t *testing.T) {
	m, err := net.ResolveUDPAddr("udp", master)
	if err != nil {
		t.Error(err)
		return
	}

	s, err := net.ResolveUDPAddr("udp", slave)
	if err != nil {
		t.Error(err)
		return
	}

	key := getPrivKey()

	service := NewNATService(key, m, s)

	go service.Start()
	time.Sleep(5)
	service.Close()
}
