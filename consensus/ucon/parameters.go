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
	"math"
	"math/big"
)

// For: the probability of K's nodes be choosed
func ProbabilityForLimitedSampleing(communitySize int64, threshold float64, k uint32) float64 {
	pFloat := float64(threshold) / float64(communitySize)
	biValue, _ := binomial(big.NewInt(int64(k)), big.NewInt(communitySize), new(big.Float).SetFloat64(pFloat)).Float64()
	return biValue
}

// For: the probability of K's nodes be k where community size is big enough
func ProbabilityForSampleing(threshold float64, k uint32) float64 {
	result := float64(1)
	for i := uint32(1); i <= k; i++ {
		result = result * threshold / float64(i)
	}
	result = result * math.Exp(-threshold)

	return result
}

func ProbabilityForViolateCondition1(honest, threshold, portion float64) float64 {
	result := float64(1)

	total := threshold * portion
	honestThreshold := float64(threshold) * honest
	for k := float64(0); k <= total; k += 1 {
		result = result + ProbabilityForSampleing(honestThreshold, uint32(k))
	}

	result = result * math.Exp(-honestThreshold)

	return result
}

//func ProbabilityForViolateCondition2(honest float64, threshold float64, portion float64) float64 {
//	result := float64(1)
//	total := threshold * portion
//	honestThreshold := threshold * honest
//
//	for k := float64(0); k <= total; k += 1 {
//		result = result + ProbabilityForSampleing(honestThreshold, uint32(k))
//	}
//
//	result = result * math.Exp(-honestThreshold)
//
//	return result
//}

//func GetVoteIntervals(communitySize uint32, minInterval uint32) []uint32 {
//	var voteIntervals []uint32
//
//	for start := uint32(minInterval * 2); start < communitySize; start = start * 2 {
//		voteIntervals = append(voteIntervals, start)
//	}
//	return voteIntervals
//}
