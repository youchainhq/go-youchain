// Copyright 2020 The go-ethereum Authors
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

// +build none

/*

   The mkalloc tool creates the genesis allocation constants in genesis_alloc.go and validators constants in genesis_validators.go
   It outputs a const declaration that contains an RLP-encoded list of (address, balance) tuples.

       go run mkalloc.go genesis.json

*/
package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strconv"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/rlp"
)

type storageItem struct {
	Key, Value common.Hash
}
type allocItem struct {
	Addr, Balance *big.Int
	StorageList   []storageItem
	Code          []byte
}

type valItem struct {
	Addr *big.Int
	Val  core.GenesisValidator
}

type allocList []allocItem

func (a allocList) Len() int           { return len(a) }
func (a allocList) Less(i, j int) bool { return a[i].Addr.Cmp(a[j].Addr) < 0 }
func (a allocList) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func makelist(g *core.Genesis) allocList {
	a := make(allocList, 0, len(g.Alloc))
	for addr, account := range g.Alloc {
		if account.Nonce != 0 {
			panic(fmt.Sprintf("illegal nonce of account %x", addr))
		}
		bigAddr := new(big.Int).SetBytes(addr.Bytes())
		item := allocItem{Addr: bigAddr, Balance: account.Balance}
		if len(account.Storage) > 0 {
			item.StorageList = make([]storageItem, 0, len(account.Storage))
			for key, value := range account.Storage {
				item.StorageList = append(item.StorageList, storageItem{key, value})
			}
		}
		if len(account.Code) > 0 {
			item.Code = account.Code
		}
		a = append(a, item)
	}
	sort.Sort(a)
	return a
}

func makeValList(g *core.Genesis) []valItem {
	v := make([]valItem, 0, len(g.Validators))
	for addr, val := range g.Validators {
		bigAddr := new(big.Int).SetBytes(addr.Bytes())
		v = append(v, valItem{bigAddr, val})
	}
	sort.Slice(v, func(i, j int) bool {
		return v[i].Addr.Cmp(v[j].Addr) < 0
	})
	return v
}

func makealloc(g *core.Genesis) string {
	a := makelist(g)
	return encode(a)
}

func makeVals(g *core.Genesis) string {
	v := makeValList(g)
	return encode(v)
}

func encode(val interface{}) string {
	data, err := rlp.EncodeToBytes(val)
	if err != nil {
		panic(err)
	}
	return strconv.QuoteToASCII(string(data))
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: mkalloc genesis.json")
		os.Exit(1)
	}

	g := new(core.Genesis)
	file, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	if err := json.NewDecoder(file).Decode(g); err != nil {
		panic(err)
	}
	fmt.Println("const allocData =", makealloc(g))

	fmt.Println("const validatorsData =", makeVals(g))
}
