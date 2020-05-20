package core

import (
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
)

func StakingRootForNewBlock(frequency uint64, parent *types.Header) common.Hash {
	height := parent.Number.Uint64()
	if (height+1)%frequency == 0 {
		return common.Hash{}
	}
	return parent.StakingRoot
}

func ResetStakingTrieOnNewPeriod(frequency, currentRound uint64, state *state.StateDB) {
	if currentRound%frequency == 0 {
		state.ResetStakingTrie()
	}
}
