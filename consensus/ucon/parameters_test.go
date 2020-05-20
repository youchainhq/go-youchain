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
	"testing"

	"github.com/youchainhq/go-youchain/logging"
)

func TestProbabilityForLimitedSampleing(t *testing.T) {
	threshold := float64(26)
	total := int64(500)
	maxCount := uint64(70) //uint64(70)
	minCount := uint64(1)  //uint64(1)
	totalProbability := float64(0)
	for i := minCount; i <= maxCount; i += 1 {
		result := ProbabilityForLimitedSampleing(total, threshold, uint32(i))
		totalProbability += result
		logging.Info("ProbabilityForLimitedSampleing", "result", result)
	}
	logging.Info("Total Probability", "p", totalProbability)
}

func TestProbabilityForSampleing(t *testing.T) {
	threshold := float64(26) //uint64(26)
	maxCount := uint64(70)   //uint64(70)
	minCount := uint64(0)    //uint64(1)
	totalProbability := float64(0)
	for i := minCount; i <= maxCount; i += 1 {
		result := ProbabilityForSampleing(threshold, uint32(i))
		totalProbability += result
		logging.Info("ProbabilityForSampleing", "result", result)
	}
	logging.Info("Total Probability", "p", totalProbability)
}

func TestProbabilityForViolateCondition1(t *testing.T) {
	threshold := float64(250)
	honest := float64(0.9)
	portion := float64(0.685)
	result := ProbabilityForViolateCondition1(honest, threshold, portion)
	logging.Info("probability for interval sampling", "result", result)
}

//func TestGetVoteIntervals(t *testing.T) {
//	intervals := GetVoteIntervals(uint32(500), DefaultMinSilentDiff)
//	log.Info(intervals)
//}
