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

package ucon

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/crypto/vrf"
	"github.com/youchainhq/go-youchain/crypto/vrf/secp256k1"
	"github.com/youchainhq/go-youchain/logging"

	"github.com/stretchr/testify/assert"
)

var (
	sk, pk     = secp256k1VRF.GenerateKey()
	seed       = common.HexToHash("0xaa624d806402ab4f06e70b6491ad21d270c86024356b8a1fbcadb5f0945d0984")
	index      = uint32(1)
	role       = uint32(2)
	threshold  = uint64(8)
	stake      = big.NewInt(10)
	totalStake = big.NewInt(1000)
)

func TestVrfSortitionFair(t *testing.T) {
	test := math.Pow(float64(33), float64(7))
	logging.Info("TestVrfSortitionFair", "test", test)

	rand.Seed(time.Now().Unix())
	totalStake := int64(50)
	lookBackSeed := common.HexToHash("0x426d37d848d43b618e83e0ce2c7d4e9edab940d2b03249b6e7733e40394fd3a5")
	proposerThreshold := uint64(26)
	sk1, _ := crypto.GenerateKey()
	vrfSk1, _ := secp256k1VRF.NewVRFSigner(sk1)
	stake1 := int64(1)

	currentRound := int64(1)
	totalVotes1 := uint32(0)
	for i := 0; i < 1000; i++ {
		_, _, subUsers1 := VrfSortition(vrfSk1, lookBackSeed, uint32(1), UConStepPrevote, proposerThreshold, big.NewInt(stake1), big.NewInt(totalStake))
		totalVotes1 += subUsers1
		logging.Info("Sub-Users", "subUsers1", subUsers1)
		currentRound += 1
	}
	logging.Info("Total votes", "totalVotes1", totalVotes1)
}

func TestVrfSortition(t *testing.T) {
	sk, _ := secp256k1VRF.GenerateKey()

	//log.Info(time.Now())
	seedtmp := common.HexToHash("0x388582ae9408aea9a2789980a52c9a7f3953ac287777f7503ac189afe434dae8")
	total := big.NewInt(267500000)
	th := uint64(2000)
	s1 := big.NewInt(8880000)
	s2 := big.NewInt(1580000)
	VrfSortition(sk, seedtmp, uint32(1), uint32(2), th, s1, total)
	//log.Info(time.Now(), subusers)

	VrfSortition(sk, seedtmp, uint32(1), uint32(2), th, s2, total)
	//log.Info(time.Now(), subusers)

	//log.Info(time.Now())
	total = big.NewInt(267500)
	th = uint64(2000)
	s1 = big.NewInt(8880)
	s2 = big.NewInt(1580)
	VrfSortition(sk, seedtmp, uint32(1), uint32(4), th, s1, total)
	//log.Info(time.Now(), subusers)

	VrfSortition(sk, seedtmp, uint32(1), uint32(4), th, s2, total)
	//log.Info(time.Now(), subusers)

	//sk, pk := secp256k1VRF.GenerateKey()
	//_, proof, _ := VrfSortition(sk, seed, uint32(1), role, threshold, stake, totalStake)
	//valid, _ := VrfVerifySortition(pk, seed, uint32(1), role, proof, threshold, stake, totalStake)
	//logging.Info("valid", valid)
	//
	//overCounts := 0
	//maxUsers := float64(threshold) * ValidatorProportionThreshold
	//for k := 1; k < 1000; k++ {
	//	totalUsers := uint32(0)
	//	for i := 1; i < 10; i++ {
	//		skSingle, _ := secp256k1VRF.GenerateKey()
	//		_, _, j := VrfSortition(skSingle, seed, uint32(1), role, threshold, stake, totalStake)
	//		//if j > 0 {
	//		//	log.Printf("VrfSortition: %d", j)
	//		//}
	//		totalUsers += j
	//	}
	//	//log.Info(totalUsers)
	//	if float64(totalUsers) > maxUsers-1 {
	//		overCounts += 1
	//	}
	//}
	//logging.Info(overCounts)
}

func TestChamberSortition(t *testing.T) {
	rand.Seed(time.Now().Unix())
	nodesCount := 87
	stakeList := make([]int64, nodesCount)
	totalStake := int64(0)
	stake1 := int64(888) //rand.Int63n(int64(100))
	for i := 0; i < 9; i++ {
		stakeList[i] = stake1 * 10000
		totalStake += stake1 * 10000
	}
	stake2 := int64(158) //rand.Int63n(int64(100))
	for i := 9; i < 81; i++ {
		stakeList[i] = stake2 * 10000
		totalStake += stake2 * 10000
	}
	for i := 81; i < 87; i++ {
		stakeList[i] = stake1 * 10000
		totalStake += stake1 * 10000
	}
	th := 2000
	minimalVotes := uint32(float64(th) * ValidatorProportionThreshold)
	logging.Info("StakeInfo", "minimalVotes", minimalVotes, "totalStake", totalStake)

	failedSeed := common.HexToHash("0x426d37d848d43b618e83e0ce2c7d4e9edab940d2b03c49b6e7733e40394fd1a5")
	failCount := 0
	overCount, overTh := 0, 54
	maxNodes, minNodes := 0, overTh
	for i := 0; i < 100; i++ {
		validators := 0
		nodes := 0
		for j := 0; j < nodesCount; j++ {
			sk, _ := crypto.GenerateKey()
			vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)

			_, _, subUsers := VrfSortition(vrfSk, failedSeed, uint32(1), UConStepPrevote, uint64(th),
				big.NewInt(stakeList[j]), big.NewInt(totalStake))
			if subUsers > 0 {
				validators += int(subUsers)
				nodes += 1
				//logging.Info("subusers", "users", subUsers)
			}
			if uint32(validators) >= minimalVotes {
				if nodes > maxNodes {
					maxNodes = nodes
				}
				if nodes < minNodes {
					minNodes = nodes
				}
				logging.Info("validators", "validator", validators, "nodes", nodes)
				break
			}
		}
		if uint32(validators) < minimalVotes {
			failCount += 1
			logging.Error("not enough votes", "validators", validators)
		}
		if nodes > overTh {
			overCount += 1
		}
	}
	logging.Info("overTh", "count", overCount, "maxNodes", maxNodes, "minNodes", minNodes)
}

func TestHouseSortition(t *testing.T) {
	t.SkipNow() //run on need
	rand.Seed(time.Now().Unix())
	nodesCount := 556
	stakeList := make([]int64, nodesCount)
	totalStake := int64(0)
	stake1 := int64(5) //rand.Int63n(int64(100))
	for i := 0; i < nodesCount; i++ {
		stakeList[i] = stake1 * 10000
		totalStake += stake1 * 10000
	}
	th := 2000
	minimalVotes := uint32(float64(th) * ValidatorProportionThreshold)
	logging.Info("StakeInfo", "minimalVotes", minimalVotes, "totalStake", totalStake)

	failedSeed := common.HexToHash("0x426d37d848d43b618e83e0ce2c7d4e9edab940d2b03c49b6e7733e40394fd1a5")
	failCount := 0
	overCount, overTh := 0, 408
	maxNodes, minNodes := 0, overTh
	for i := 0; i < 100; i++ {
		validators := 0
		nodes := 0
		for j := 0; j < nodesCount; j++ {
			sk, _ := crypto.GenerateKey()
			vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)

			_, _, subUsers := VrfSortition(vrfSk, failedSeed, uint32(1), UConStepPrevote, uint64(th),
				big.NewInt(stakeList[j]), big.NewInt(totalStake))
			if subUsers > 0 {
				validators += int(subUsers)
				nodes += 1
				//logging.Info("subusers", "users", subUsers)
			}
			if uint32(validators) >= minimalVotes {
				if nodes > maxNodes {
					maxNodes = nodes
				}
				if nodes < minNodes {
					minNodes = nodes
				}
				logging.Info("validators", "validator", validators, "nodes", nodes)
				break
			}
		}
		if uint32(validators) < minimalVotes {
			failCount += 1
			logging.Error("not enough votes", "validators", validators)
		}
		if nodes > overTh {
			overCount += 1
		}
	}
	logging.Info("overTh", "count", overCount, "maxNodes", maxNodes, "minNodes", minNodes)
}

func TestStakeProportion(t *testing.T) {
	stake1, stake2 := 888, 158
	totalStake := stake1*15 + stake2*72
	count1 := 8
	count2 := 49
	result := float64(stake1*count1+stake2*count2) / float64(totalStake)
	logging.Info("pro", "value", result)
}

func TestValidatorCount(t *testing.T) {
	rand.Seed(time.Now().Unix())
	nodesCount := 5
	stakeList := make([]int64, nodesCount)
	totalStake := int64(0)
	for i := 0; i < nodesCount; i++ {
		stake := int64(8) //rand.Int63n(int64(100))
		stakeList[i] = stake * 10000
		totalStake += stake * 10000
	}
	logging.Info("StakeInfo", "totalStake", totalStake, "stakeList", stakeList)
	failedSeed := common.HexToHash("0x426d37d848d43b618e83e0ce2c7d4e9edab940d2b03c49b6e7733e40394fd1a5")

	validatorThreshold := int64(600)                                                   //int64(DefaultValidatorThreshold)
	minimalVotes := uint32(float64(validatorThreshold) * ValidatorProportionThreshold) //float64(validatorThreshold) * ValidatorProportionThreshold
	logging.Info("minimalVotes", "Minimal votes", minimalVotes)
	failCount := 0
	for i := 0; i < 10; i++ {
		// get validator count
		validators := 0
		nodes := 0
		for j := 0; j < nodesCount; j++ {
			sk, _ := crypto.GenerateKey()
			vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)

			_, _, subUsers := VrfSortition(vrfSk, failedSeed, uint32(1), UConStepPrevote, uint64(validatorThreshold),
				big.NewInt(stakeList[j]), big.NewInt(totalStake))
			if subUsers > 0 {
				validators += int(subUsers)
				nodes += 1
				logging.Info("subusers", "users", subUsers)
			}
			if uint32(validators) >= minimalVotes {
				logging.Info("validators", "validator", validators, "nodes", nodes)
				break
			}
		}

		if uint32(validators) <= minimalVotes {
			failCount += 1
			logging.Error("not enough votes", "validators", validators)
		}
	}
	logging.Info("Fail count", "failCount", failCount)
}

func TestVrfSortitionVotesCount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}
	rand.Seed(time.Now().Unix())
	nodesCount := 50
	stakeList := make([]int64, nodesCount)
	totalStake := int64(0)
	for i := 0; i < nodesCount; i++ {
		stake := int64(10) //rand.Int63n(int64(1000))
		stakeList[i] = stake
		totalStake += stake
	}
	logging.Info("stake", "stakeList", stakeList)
	//totalStake = int64(float64(totalStake) * 100.0)
	failedSeed := common.HexToHash("0x426d37d848d43b618e83e0ce2c7d4e9edab940d2b03c49b6e7733e40394fd1a5")

	validatorThreshold := int64(float64(totalStake) * 0.7)
	//totalStake = int64(float64(totalStake) * 10.0)
	minimalVotes := uint32(float64(validatorThreshold)*ValidatorProportionThreshold - 1) //float64(validatorThreshold) * ValidatorProportionThreshold
	logging.Info("Minimal votes", "minimalVotes", minimalVotes)
	failCount := 0
	for i := 0; i < 10; i++ {
		// get validator count
		validators := 0
		for j := 0; j < nodesCount; j++ {
			sk, _ := crypto.GenerateKey()
			vrfSk, _ := secp256k1VRF.NewVRFSigner(sk)

			_, _, subUsers := VrfSortition(vrfSk, failedSeed, uint32(1), UConStepPrevote, uint64(validatorThreshold),
				big.NewInt(stakeList[j]), big.NewInt(totalStake))
			if subUsers > 0 {
				validators += int(subUsers)
			}
			//log.Info("Sub-Users", subUsers, "hash", hash.String())
		}
		logging.Info("validator", "validators", validators)
		if uint32(validators) <= minimalVotes {
			failCount += 1
			logging.Error("not enough votes", "validators", validators, "minimalVotes", minimalVotes)
		}
	}
	logging.Info("Fail count", "failCount", failCount)
}

func TestVrfVerifyPriority(t *testing.T) {
	value, proof, j := VrfSortition(sk, seed, index, role, threshold, stake, totalStake)

	priority := VrfComputePriority(value, j)

	ret, err := VrfVerifyPriority(pk, seed, index, role, proof, priority, j, threshold, stake, totalStake)
	if !ret {
		t.Fatal("error verify")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestVrfComputePriority(t *testing.T) {
	value, proof, j := VrfSortition(sk, seed, uint32(1), role, threshold, stake, totalStake)

	priority := VrfComputePriority(value, j)

	logging.Info("VrfComputePriority", "proof", proof, "priority", priority)
}

func TestComparePriority(t *testing.T) {
	value1, _, j1 := VrfSortition(sk, seed, uint32(1), role, threshold, stake, totalStake)
	priority1 := VrfComputePriority(value1, j1)

	sk2, _ := secp256k1VRF.GenerateKey()
	stake2 := big.NewInt(30)

	value2, _, j2 := VrfSortition(sk2, seed, uint32(1), role, threshold, stake2, totalStake)

	priority2 := VrfComputePriority(value2, j2)

	assert.NotEqual(t, priority1, priority2)
}

func TestBig(t *testing.T) {
	bts := []byte{0x2, 0x10, 0x10, 0x10}

	b := big.NewInt(0).SetBytes(bts)

	max := common.Big2().Exp(common.Big2(), big.NewInt(8*int64(len(bts))), nil)

	res := new(big.Float).Quo(new(big.Float).SetInt(b), new(big.Float).SetInt(max))

	logging.Info("res", "res", res)
}

func TestBinomial(t *testing.T) {
	n := big.NewInt(10)
	p := big.NewFloat(0.1)

	totalP := new(big.Float)
	for i := int64(0); i <= 10; i++ {
		b := binomial(big.NewInt(i), n, p)
		totalP = totalP.Add(totalP, b)
		fmt.Printf("%d:%s\n", i, b.String())
	}
	fmt.Println("totalP: ", totalP.String())

	maxDiff := new(big.Float).SetFloat64(0.00001)
	one := new(big.Float).SetFloat64(1.0)
	max := new(big.Float).Add(one, maxDiff)
	min := new(big.Float).Sub(one, maxDiff)
	if totalP.Cmp(min) < 0 || totalP.Cmp(max) > 0 {
		t.Fail()
	}
}

func TestGetVotes(t *testing.T) {
	var tau, W int64 = 200, 1e9
	p := float64(tau) / float64(W)
	fp := new(big.Float).Quo(new(big.Float).SetInt64(tau), new(big.Float).SetInt64(W))
	logging.Info(fmt.Sprintf("p: %f  fp: %s\n", p, fp.Text('g', 8)))

	type item struct {
		hash common.Hash
		w    *big.Int
		want *big.Int
	}

	items := []item{
		{hash: common.HexToHash("0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff"), w: big.NewInt(1000), want: big.NewInt(0)},
		{hash: common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), w: big.NewInt(1000), want: big.NewInt(1000)},
	}
	for _, it := range items {
		got := getVotes(it.hash, it.w, fp)
		if got.Cmp(it.want) != 0 {
			t.Errorf("want: %s  got: %s\n", it.want.String(), got.String())
		}
	}
}

func TestChooseAndGetVotes(t *testing.T) {
	type item struct {
		tau, W, w *big.Int
	}
	items := []item{
		{tau: big.NewInt(500), W: big.NewInt(1e9), w: big.NewInt(1000000)},
		{tau: big.NewInt(200), W: big.NewInt(1e8), w: big.NewInt(2000)},
	}
	n := 1000
	hashs := make([]common.Hash, n)
	for i := 0; i < n; i++ {
		rand.Read(hashs[i][:])
	}
	//hashs[n-3] = common.HexToHash("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd")
	//hashs[n-2] = common.HexToHash("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe")
	//hashs[n-1] = common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

	for _, it := range items {
		fp := new(big.Float).Quo(new(big.Float).SetInt(it.tau), new(big.Float).SetInt(it.W))
		p, _ := fp.Float64()
		for _, h := range hashs {
			hb := new(big.Int).SetBytes(h[0:])
			bigValue := new(big.Float).Quo(new(big.Float).SetInt(hb), new(big.Float).SetInt(maxVrfHashValue))
			got1 := getVotes(h, it.w, fp)
			got2 := choose(h, it.w, p)
			if got1.Int64() != got2 {
				t.Errorf("tau: %d  W: %d  w: %d  fp: %s  p: %e  hash: %s  got1: %d  got2: %d  %s\n",
					it.tau.Int64(), it.W.Int64(), it.w.Int64(), fp.Text('e', 16), p, h.String(), got1.Int64(), got2, bigValue.Text('f', 128))
			} else if got2 > 0 {
				t.Logf("tau: %d  W: %d  w: %d  fp: %s  p: %e  hash: %s  got: %d  %s\n",
					it.tau.Int64(), it.W.Int64(), it.w.Int64(), fp.Text('e', 16), p, h.String(), got2, bigValue.Text('f', 128))

			}
		}
	}
}

func TestChoose(t *testing.T) {
	type item struct {
		tau, W, w *big.Int
	}
	items := []item{
		//{tau:big.NewInt(500),W:big.NewInt(1e9),w:big.NewInt(1000000)},
		{tau: big.NewInt(100), W: big.NewInt(1e8), w: big.NewInt(1000000)},
	}
	n := 100
	hashs := make([]common.Hash, n)
	for i := 0; i < n-3; i++ {
		rand.Read(hashs[i][:])
	}
	hashs[n-4] = common.HexToHash("0xe666666666666665ffffffffffffffffffffffffffffffffffffffffffffffff") //v=0.9
	hashs[n-3] = common.HexToHash("0xffffffffffffffffffffff000000000000000000000000000000000000000000")
	hashs[n-2] = common.HexToHash("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe")
	hashs[n-1] = common.HexToHash("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

	for _, it := range items {
		fp := new(big.Float).Quo(new(big.Float).SetInt(it.tau), new(big.Float).SetInt(it.W))
		p, _ := fp.Float64()
		for _, h := range hashs {
			//got1 := getVotes(h,it.w,fp)
			got2 := choose(h, it.w, p)
			if got2 > 0 {
				fmt.Println(h.String(), got2)

			}
			//if got1.Int64() != got2 {
			//	t.Errorf("tau: %d  W: %d  w: %d  fp: %s  p: %e  hash: %s  got1: %d  got2: %d\n",
			//		it.tau.Int64(),it.W.Int64(),it.w.Int64(),fp.Text('e',16),p,h.String(),got1.Int64(),got2)
			//}
		}
	}
}

func TestSybilAttackRisk(t *testing.T) {
	t.SkipNow() //run on need
	n := 51
	expectSize := uint64(2000)
	total, myStake := big.NewInt(1e9), big.NewInt(5e7)
	perSybilStake := new(big.Int).Div(myStake, big.NewInt(int64(n-1)))
	sks := make([]vrf.PrivateKey, 0, n)

	for i := 0; i < n; i++ {
		sk, _ := secp256k1VRF.GenerateKey()
		sks = append(sks, sk)
	}

	rand.Seed(time.Now().Unix())
	var seed common.Hash
	rand.Read(seed[:])

	cnt, risk, rt, advantage, at := 1000, 0, 0, 0, 0
	for i := 0; i < cnt; i++ {
		_, _, myVotes := VrfSortition(sks[0], seed, 1, UConStepPrevote, expectSize, myStake, total)
		var sybilTotal uint32
		for j := 1; j < n; j++ {
			_, _, sybilVote := VrfSortition(sks[j], seed, 1, UConStepPrevote, expectSize, perSybilStake, total)
			if sybilVote > 0 {
				sybilTotal += sybilVote
			}
		}
		rt += int(sybilTotal)
		at += int(myVotes)
		if myVotes < sybilTotal {
			risk++
			fmt.Println("sybil  win", seed.String(), myVotes, sybilTotal)
		} else if myVotes > sybilTotal {
			advantage++
			fmt.Println("honest win", seed.String(), myVotes, sybilTotal)
		}
		rand.Read(seed[:])
	}
	fmt.Printf("total: %d , honest win: %d, votes: %d, sybils win %d, votes: %d \n", cnt, advantage, at, risk, rt)
	if risk > advantage+advantage/20 {
		t.Errorf("potential sybil attack risk")
	}
}

//func BenchmarkGetVotes(b *testing.B) {
//	b.StopTimer()
//	var tau, W int64 = 200, 1e9
//	fp := new(big.Float).Quo(new(big.Float).SetInt64(tau), new(big.Float).SetInt64(W))
//	keys := make([]common.Hash, b.N)
//	for i := 0; i < b.N; i++ {
//		rand.Read(keys[i][:])
//	}
//	w := new(big.Int).SetInt64(1000000)
//	b.StartTimer()
//	for i := 0; i < b.N; i++ {
//		getVotes(keys[i], w, fp)
//	}
//
//	//result record:
//	//2019-07-01 fix precision
//	//BenchmarkGetVotes-4   	    5000	    313949 ns/op
//	//BenchmarkGetVotes-4   	    3000	    334762 ns/op
//}

func BenchmarkChoose(b *testing.B) {
	b.StopTimer()
	var tau, W int64 = 2000, 1e6
	fp, _ := new(big.Float).Quo(new(big.Float).SetInt64(tau), new(big.Float).SetInt64(W)).Float64()
	keys := make([]common.Hash, b.N)
	for i := 0; i < b.N; i++ {
		rand.Read(keys[i][:])
	}
	w := new(big.Int).SetInt64(W / 100)
	//b.Logf("tau: %d W: %d w: %d \n", tau, W, w)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		choose(keys[i], w, fp)
	}
}

func BenchmarkVrfVerifySortition(b *testing.B) {
	sk, pk := secp256k1VRF.GenerateKey()
	var proof []byte
	var j uint32
	for true {
		_, proof, j = VrfSortition(sk, seed, uint32(1), role, 2000, big.NewInt(1e4), big.NewInt(1e6))
		if j > 0 {
			break
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VrfVerifySortition(pk, seed, uint32(1), role, proof, 1, 2000, big.NewInt(1e4), big.NewInt(1e6))
	}
}

func BenchmarkVrfSortition(b *testing.B) {
	sk, _ := secp256k1VRF.GenerateKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VrfSortition(sk, seed, uint32(i+1), role, 2000, big.NewInt(1e4), big.NewInt(1e6))
	}
}
