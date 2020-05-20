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
	"sort"
	"strings"

	"github.com/hashicorp/golang-lru"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/params"
)

//votesWatcher run as a votes watcher to checkout inactive validators
type votesWatcher struct {
	chain  consensus.ChainReader
	engine engine
	cache  *lru.TwoQueueCache // height => inactive validators
}

type votePair struct {
	Required uint `json:"r"`
	Voted    uint `json:"v"`
}

//newVotesWatcher constructor
func newVotesWatcher(bc consensus.ChainReader, engine engine) *votesWatcher {
	cache, _ := lru.New2Q(1024)
	return &votesWatcher{
		chain:  bc,
		engine: engine,
		cache:  cache,
	}
}

//Inactive return sorted inactive addresses
func (w *votesWatcher) Inactive(latest uint64, checkRange uint64) []common.Address {
	pr, err := w.chain.VersionForRound(latest)
	if err != nil || !pr.EnableInactivity {
		return []common.Address{}
	}

	if latest < checkRange {
		return []common.Address{}
	}

	votePairs := make(map[common.Address]*votePair)
	start := latest - uint64(params.MaxVoteCacheCount) - checkRange
	end := start + checkRange - 1
	for height := start; height <= end; height++ {
		if latest <= uint64(height) {
			continue
		}

		var (
			votes map[common.Address]bool
			err   error
		)
		cached, ok := w.cache.Get(height)
		if !ok {
			header := w.chain.GetHeaderByNumber(height)
			if header != nil {
				log.Debug("inactive check validator", "latest", latest, "height", header.Number, "validators", hexutil.Encode(header.Validator))
				votes, err = w.engine.CheckValidatorVotes(w.chain, header)
				if err != nil {
					log.Error("check validator votes failed", "height", header.Number, "err", err)
				} else {
					w.cache.Add(height, votes)
				}
			}
		} else {
			votes = cached.(map[common.Address]bool)
		}

		for addr, voted := range votes {
			pair, _ := votePairs[addr]
			if pair == nil {
				pair = &votePair{}
			}
			pair.Required++
			if voted {
				pair.Voted++
			}
			votePairs[addr] = pair
		}
	}

	var inactiveAddresses []common.Address
	var output []string
	for address, pair := range votePairs {
		var m bool
		if uint64(pair.Required) < checkRange {
			continue
		}
		f := float64(pair.Voted) / float64(pair.Required)
		if f < inactiveThreshold {
			inactiveAddresses = append(inactiveAddresses, address)
			m = true
		}
		output = append(output, fmt.Sprintf("%s:v=%d:r=%d:m=%v:f=%.2f", address.String(), pair.Voted, pair.Required, m, f))
	}

	if len(inactiveAddresses) > 0 {
		log.Info("inactive", "height", latest, "data", strings.Join(output, ";"))
		sortedAddresses := common.SortedAddresses(inactiveAddresses)
		sort.Sort(sortedAddresses)
		return sortedAddresses
	}
	return inactiveAddresses
}
