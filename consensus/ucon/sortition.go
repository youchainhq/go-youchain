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
	"encoding/binary"
	"fmt"
	"math/big"
	"reflect"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/crypto/vrf"
	"github.com/youchainhq/go-youchain/logging"

	"github.com/ALTree/bigfloat"
	"gonum.org/v1/gonum/stat/distuv"
)

func VrfSortition(sk vrf.PrivateKey, seed common.Hash, index uint32, role uint32, threshold uint64, stake, totalStake *big.Int) (common.Hash, []byte, uint32) {
	if totalStake.Sign() == 0 {
		logging.Error("totalStake is 0.")
		return common.Hash{}, nil, uint32(0)
	}

	//logging.Debug("VrfSortition Start.", "index", index, "step", role, "threshold", threshold, "stake", stake, "totalStake", totalStake)
	var m = MakeM(seed, role, index)

	pFloat, _ := new(big.Float).Quo(new(big.Float).SetUint64(threshold), new(big.Float).SetInt(totalStake)).Float64()

	value, proof, j := sortition(sk, m, stake, pFloat)

	//logging.Debug("VrfSortition Finished.", "sub-users", j)

	return value, proof, uint32(j)
}

func VrfVerifySortition(pk vrf.PublicKey, seed common.Hash, index uint32, role uint32, proof []byte, subUsers uint32, threshold uint64, stake, totalStake *big.Int) (bool, error) {
	if totalStake.Sign() == 0 {
		return false, fmt.Errorf("totalStake is 0.")
	}
	var m = MakeM(seed, role, index)
	hash, err := pk.ProofToHash(m, proof)
	if err != nil {
		return false, fmt.Errorf("verify seed failed.")
	}

	pFloat, _ := new(big.Float).Quo(new(big.Float).SetUint64(threshold), new(big.Float).SetInt(totalStake)).Float64()
	j := choose(hash, stake, pFloat)
	if j <= 0 {
		return false, fmt.Errorf("not a validator.")
	}
	if uint32(j) != subUsers {
		return false, fmt.Errorf("sub-users' number is not correct:%x,%x", j, subUsers)
	}

	return true, nil
}

func VrfComputePriority(hash common.Hash, j uint32) common.Hash {
	return computePriority(hash, new(big.Int).SetUint64(uint64(j)))
}

// proof: sortition proof
func VrfVerifyPriority(pk vrf.PublicKey, seed common.Hash, index uint32, role uint32, proof []byte, priority common.Hash, subUsers uint32, threshold uint64, stake, totalStake *big.Int) (bool, error) {
	if totalStake.Int64() == 0 {
		return false, fmt.Errorf("totalStake is 0.")
	}
	var m = MakeM(seed, role, index)

	hash, err := pk.ProofToHash(m, proof)
	if err != nil {
		return false, fmt.Errorf("verify seed failed")
	}

	pFloat, _ := new(big.Float).Quo(new(big.Float).SetUint64(threshold), new(big.Float).SetInt(totalStake)).Float64()
	j := choose(hash, stake, pFloat)
	if uint32(j) != subUsers {
		return false, fmt.Errorf("sub-users' number is not correct:%x,%x", j, subUsers)
	}

	p := computePriority(hash, big.NewInt(j))
	return reflect.DeepEqual(p, priority), nil
}

func computePriority(hash common.Hash, j *big.Int) common.Hash {
	//loop from 0->j
	//find max
	//var max common.Hash
	max := common.Hash{}
	maxInt := new(big.Int).SetBytes(max[:])
	for i := big.NewInt(0); i.Cmp(j) <= 0; i = new(big.Int).Add(i, common.Big1()) {
		var concat []byte
		concat = append(concat, hash[:]...)
		concat = append(concat, i.Bytes()...)

		h := crypto.Keccak256Hash(concat)

		hashInt := new(big.Int).SetBytes(h[:])

		if hashInt.Cmp(maxInt) > 0 {
			maxInt = hashInt
			max = h
		}
	}

	return max
}

func sortition(sk vrf.PrivateKey, m []byte, w *big.Int, p float64) (common.Hash, []byte, int64) {
	value, proof := sk.Evaluate(m)
	j := choose(value, w, p)
	return value, proof, j
}

//Deprecated: for performance reason, use choose instead.
func getVotes(hash common.Hash, w *big.Int, p *big.Float) *big.Int {
	hb := new(big.Int).SetBytes(hash[0:])
	//value=hb/maxVrfHashValue
	value := new(big.Float).Quo(new(big.Float).SetInt(hb), new(big.Float).SetInt(maxVrfHashValue))
	//log.Debug("getVotes", "w", w, "p", p, "hash", hash.String(), "max", maxVrfHashValue.Text(16), "val", value)
	//
	curr := new(big.Float) // cdf of j
	for j := big.NewInt(0); j.Cmp(w) <= 0; j = new(big.Int).Add(j, common.Big1()) {
		curr = curr.Add(curr, binomial(j, w, p))
		if value.Cmp(curr) < 0 {
			return j
		}
	}

	return new(big.Int).Set(w)
}

func binomial(k, w *big.Int, p *big.Float) *big.Float {
	ip := new(big.Float).Sub(big.NewFloat(1.0), p)
	if k.Uint64() == 0 {
		r := bigfloat.Pow(ip, new(big.Float).SetInt(w))
		return r
	}

	f := func(k, w *big.Int, p, ip *big.Float) *big.Float {
		a := new(big.Int).Binomial(w.Int64(), k.Int64())

		b := bigfloat.Pow(p, new(big.Float).SetInt(k))
		c := bigfloat.Pow(ip, new(big.Float).SetInt(new(big.Int).Sub(w, k)))

		ab := new(big.Float).Mul(new(big.Float).SetInt(a), b)
		abc := new(big.Float).Mul(ab, c)
		return abc
	}

	//f(k;w,p) = f(w-k;w,1-p)
	if new(big.Int).Mul(k, big.NewInt(2)).Cmp(w) > 0 {
		return f(new(big.Int).Sub(w, k), w, ip, p)
	}
	return f(k, w, p, ip)
}

//choose is the new logic of the sortition
func choose(hash common.Hash, w *big.Int, p float64) int64 {
	hb := new(big.Int).SetBytes(hash[0:])
	if hb.Cmp(maxVrfHashValue) == 0 {
		return w.Int64()
	}
	if hb.Cmp(big.NewInt(1)) < 0 {
		return 0
	}
	//target=hb/maxVrfHashValue
	bigValue := new(big.Float).Quo(new(big.Float).SetInt(hb), new(big.Float).SetInt(maxVrfHashValue))
	target, _ := bigValue.Float64()
	n := w.Int64()
	binom := distuv.Binomial{N: float64(n), P: p}
	//Pr(X <= k) = F(k;n,p)
	//need to find the first j such that target <= F(j;n,p)
	if target > 0.99 {
		// target <= F(j;n,p) ==> 1-target >= 1-F(j;n,p)
		// 1-F(j;n,p) = Pr(X >= j+1) = F(n-(j+1);n,1-p)
		invValue, _ := new(big.Float).Sub(big.NewFloat(1.0), bigValue).Float64()
		invp := 1.0 - p
		binom = distuv.Binomial{N: float64(n), P: invp}
		isMatch := func(h int64) bool {
			return invValue < binom.CDF(float64(h))
		}
		k := search(n, isMatch)
		// cdf(k-1) <= invValue < cdf(k)
		// => F(k-1;n,1-p) <= 1-target < F(k;n,1-p)
		// => 1-F(k;n,1-p) < target <= 1-F(k-1;n,1-p) , 1-F(k-1;n,1-p) = 1- Pr(X <= k-1) = Pr(x >= k) = F(n-k;n,1-(1-p)) = F(n-k;n,p)
		// => F(n-(k+1);n,p) < target <= F(n-k;n,p)
		return n - k
	} else {
		isMatch := func(h int64) bool {
			return target <= binom.CDF(float64(h))
		}
		m := binom.Mean()
		// 20.0 is just an experience value for performance.
		if m < 20.0 {
			//search forward
			for j := int64(0); j <= n; j++ {
				if isMatch(j) {
					return j
				}
			}
		} else {
			//binary search : F(j-1;n,p) < target <= F(j;n,p)
			return search(n, isMatch)
		}
	}
	return w.Int64()
}

//search is the same as sort.Search, except for the index type is changed to int64.
// n must be < MaxInt64/2 because it's not considering overflow in here
func search(n int64, f func(int64) bool) int64 {
	// Invariant: f(i-1) == false, f(j) == true.
	i, j := int64(0), n
	for i < j {
		h := (i + j) >> 1 // not considering overflow here, so n must < MaxInt64/2
		// i ≤ h < j
		if !f(h) {
			i = h + 1 // preserves f(i-1) == false
		} else {
			j = h // preserves f(j) == true
		}
	}
	// i == j, f(i-1) == false, and f(j) (= f(i)) == true  =>  answer is i.
	return i
}

func MakeM(seed common.Hash, role uint32, index uint32) []byte {
	m := make([]byte, 40)

	copy(m[:32], seed.Bytes())
	copy(m[32:36], uint32ToBytes(role))
	copy(m[36:], uint32ToBytes(index))

	return m
}

func uint32ToBytes(i uint32) []byte {
	var buf = make([]byte, 4)
	binary.BigEndian.PutUint32(buf, i)
	return buf
}

func bytesToUint32(buf []byte) uint32 {
	return binary.BigEndian.Uint32(buf)
}

func uint64ToBytes(i uint64) []byte {
	var buf = make([]byte, 8)
	binary.BigEndian.PutUint64(buf, i)
	return buf
}

func bytesToUint64(buf []byte) uint64 {
	return binary.BigEndian.Uint64(buf)
}

func int8ToBytes(i uint8) []byte {
	var buf = make([]byte, 1)
	buf[0] = byte(i)
	return buf
}
