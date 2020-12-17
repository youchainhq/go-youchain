/*
 * Copyright 2020 YOUCHAIN FOUNDATION LTD.
 * This file is part of the go-youchain library.
 *
 * The go-youchain library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The go-youchain library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the go-youchain library. If not, see <http://www.gnu.org/licenses/>.
 */

package ucon

import (
	"fmt"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/crypto/vrf"
	secp256k1VRF "github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"math/big"
	"math/rand"
	"testing"
	"time"
)

func TestProposerStatistics(t *testing.T) {
	t.SkipNow() //
	rand.Seed(time.Now().Unix())
	start := time.Now()
	type Item struct {
		Id    int
		VrfSk vrf.PrivateKey
		Stake *big.Int

		BlockCnt int
		Last     int
		MaxSpan  int
		Span     []int
	}

	runTest := func(cnt1, cnt2 int) {
		nodes := make([]*Item, 0, cnt1+cnt2)
		for i := 0; i < cnt1+cnt2; i++ {
			sk, _ := crypto.GenerateKey()
			vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)
			item := &Item{
				Id:    i,
				VrfSk: vrfSk,
				Span:  make([]int, 6),
			}
			if i < cnt1 {
				item.Stake = big.NewInt(10000000)
			} else {
				item.Stake = big.NewInt(1580000)
			}
			nodes = append(nodes, item)
		}
		fmt.Println("Initialization done. elapse: ", time.Since(start))

		getSpanIdx := func(span int) int {
			idx := span / 128
			if idx >= 5 {
				return 5
			}
			return idx
		}

		ri := uint32(1)
		seed := common.Hash{}
		rand.Read(seed[:])
		total := big.NewInt(int64(10000000*cnt1) + int64(1580000*cnt2))
		maxSpan := 0

		n := 10000
		for i := 1; i <= n; i++ {
			currPrio := common.Hash{}
			var proposer *Item
			for _, node := range nodes {
				v, _, j := VrfSortition(node.VrfSk, seed, ri, 1, 26, node.Stake, total)
				if j > 0 {
					priority := VrfComputePriority(v, j)

					if CompareCommonHash(priority, currPrio) > 0 {
						proposer = node
						currPrio = priority
					}
				}
			}
			if proposer == nil {
				fmt.Println("no proposer", i, ri)
				i--
				ri++
				continue
			}
			seed, _ = ComputeSeed(proposer.VrfSk, big.NewInt(int64(i)), ri, seed)
			span := i - proposer.Last
			maxSpan = max(maxSpan, span)
			proposer.Span[getSpanIdx(span)] += 1
			proposer.Last = i
			proposer.BlockCnt++
			ri = 1

			if i%100 == 0 {
				fmt.Println(i, maxSpan, time.Since(start))
			}
		}

		fmt.Printf("n1: %d n2: %d RESULT:\n", cnt1, cnt2)
		stat := make([]int, 6)
		for _, node := range nodes {
			fmt.Printf("%d(%d)\t", node.BlockCnt, node.Last)
			span := n - node.Last
			maxSpan = max(maxSpan, span)
			node.Span[getSpanIdx(span)] += 1
			for k, v := range node.Span {
				stat[k] += v
			}
		}
		fmt.Println()

		fmt.Printf("n1: %d n2: %d RESULT:\nmaxSpan: %d\n stat: %v \n", cnt1, cnt2, maxSpan, stat)
	}

	cnt := []int{10, 15, 10, 40, 15, 10, 15, 20, 15, 30, 15, 35, 15, 40, 20, 10, 20, 20, 20, 30, 20, 40}
	for i := 0; i < len(cnt)-1; i += 2 {
		runTest(cnt[i], cnt[i+1])
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
