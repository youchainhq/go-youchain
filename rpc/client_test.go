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

package rpc

import (
	"fmt"
	"github.com/youchainhq/go-youchain/logging"
	"net/http"
	"os"
	"testing"
)

/**
curl -X POST http://localhost:3009  -H 'cache-control: no-cache' -H 'content-type: application/json' -H 'postman-token: fda5a29f-74f5-1be8-b45c-cd98b6ca70da' \
  -d '{"jsonrpc":"2.0","id":3,"method":"test_err","params":[{"Value":10000}]}'

*/
func TestNewClient(t *testing.T) {
	host := "http://0.0.0.0"
	port := 13009

	server := NewServer()
	testService := &TestService{}
	r1 := server.RegisterName("test", testService)
	if r1 != nil {
		fmt.Println(r1.Error())
		os.Exit(1)
	}
	go http.ListenAndServe(fmt.Sprintf(":%d", port), server)

	client, _ := Dial(fmt.Sprintf("%s:%d", host, port))

	var GetBigInt string
	if err := client.Call(&GetBigInt, "test_getBigInt"); err != nil {
		logging.Info(err.Error())
	} else {
		logging.Info(GetBigInt)
	}
	var GetBytes []byte
	if err := client.Call(&GetBytes, "test_getBytes", "wang", 100); err != nil {
		logging.Info(err.Error())
	} else {
		logging.Info(string(GetBytes))
	}

}
