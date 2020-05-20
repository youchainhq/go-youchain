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

package staking

import (
	"fmt"
	"testing"
)

import "github.com/stretchr/testify/assert"

// Test vote cmp.
func TestVoteCmp(t *testing.T) {
	var m bool
	pair := votePair{
		Voted:    34,
		Required: 35,
	}
	f := float64(pair.Voted) / float64(pair.Required)
	if f < inactiveThreshold {
		m = true
	}
	t.Log("result", "voted", pair.Voted, "required", pair.Required, "m", m, "f", f, "inactiveThreshold", inactiveThreshold)
	assert.False(t, m)
}

// TestVotesCheckRange .
func TestVotesCheckRange(t *testing.T) {
	sealingBlock := 90
	offset := 4
	checkRange := 10
	start := sealingBlock - offset - checkRange
	end := start + checkRange - 1
	fmt.Println("start", start, "end", end)
	assert.Equal(t, 76, start)
	assert.Equal(t, 85, end)
}
