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

package params

import (
	"github.com/youchainhq/go-youchain/common"
	"math/big"
	"sync"
	"time"
)

const (
	MainNetId = 1
	TestNetId = 2

	// NetworkIdForTestCase is used for test case so to use a different suite of parameters.
	// This value is within the range of int8, so it can acts like the MainNetId.
	NetworkIdForTestCase = 99
)

var (
	nidLock   sync.Mutex
	checkOnce sync.Once
	networkId uint64
)

// InitNetworkId initialize the networkId for once.
// It should be set according the stored genesis information
// or by user specified on the first time the client was ran.
func InitNetworkId(id uint64) {
	if id > 0 && id != networkId {
		nidLock.Lock()
		if id != networkId {
			networkId = id
			initConsensusProtocols(networkId)
		}
		nidLock.Unlock()
	}
}

// NetworkId return the current networkId.
// if the networkId is not set, it panic.
func NetworkId() uint64 {
	checkOnce.Do(func() {
		if networkId == 0 {
			panic("networkId not set")
		}
	})
	return networkId
}

// YouParams contains YOUChain protocol related parameters.
// And these parameters can be block height related.
type YouParams struct {
	// YOUChain protocol version
	Version YouVersion
	// EVM version.
	EVMVersion string

	CaravelParams
	StakingParams

	// YOUChain protocol upgrades.  Votes for upgrades are collected for
	// UpgradeVoteRounds.  If the number of positive votes is over
	// UpgradeThreshold, the proposal is accepted.
	//
	// UpgradeVoteRounds needs to be long enough to collect an
	// accurate sample of participants, and UpgradeThreshold needs
	// to be high enough to ensure that there are sufficient participants
	// after the upgrade.
	//
	// A consensus protocol upgrade may specify the delay between its
	// acceptance and its execution.  This gives clients time to notify
	// users.  This delay is specified by the upgrade proposer and must
	// be between MinUpgradeWaitRounds and MaxUpgradeWaitRounds (inclusive)
	// in the old protocol's parameters.  Note that these parameters refer
	// to the representation of the delay in a block rather than the actual
	// delay: if the specified delay is zero, it is equivalent to
	// MinUpgradeWaitRounds in the old protocol's parameters.
	ApprovedUpgradeVersion YouVersion //target version that should upgrade to
	UpgradeWaitRounds      uint64     //wait until execution after approve
	UpgradeVoteRounds      uint64     //voting rounds
	UpgradeThreshold       uint64     //voting threshold
	MinUpgradeWaitRounds   uint64
	MaxUpgradeWaitRounds   uint64
}

// CaravelParams contains parameters of the Caravel consensus
type CaravelParams struct {
	ProposerThreshold     uint64 // can use a fixed value, such as 26
	ValidatorThreshold    uint64
	CertValThreshold      uint64
	ConsensusTimeout      time.Duration
	ConsensusStepInterval time.Duration
	StakeLookBack         uint64 // look-back parameter for seed, a security parameter. can use a fixed value
	SeedLookBack          uint64
	EnableBls             bool // enable bls signature. may be deprecated due to performance or security reason.
	EnableInactivity      bool
	// Max time from current time allowed for blocks, before they're considered future blocks
	AllowedFutureBlockTime time.Duration
}

// StakingParams contains parameters of the staking module
type StakingParams struct {
	MinStakes map[ValidatorRole]uint64
	MaxStakes map[ValidatorRole]uint64
	// MinSelfStake is the minimum stake that a validator should afford by it self.
	MinSelfStakes      map[ValidatorRole]uint64
	RewardsPoolAddress common.Address
	SubsidyThreshold   uint64 // max subsidy, should less than 18*YOU, otherwise we must change the type and the related logic.
	SubsidyCoeff       uint8  // the coefficient for calculating subsidy, must between 1 and 9.
	RewardsDistRatio   map[ValidatorRole]uint64
	SignatureRequired  map[ValidatorRole]bool

	MaxRewardsPeriod     uint64
	MaxEvidenceExpiredIn uint64

	WithdrawDelay                uint64 // MUST large then CaravelParams.StakeLookBack
	WithdrawRecordRetention      uint64
	ExpelledRoundForDoubleSign   uint64
	ExpelledRoundForInactive     uint64
	PenaltyTo                    common.Address
	PenaltyFractionForDoubleSign uint64
	PenaltyFractionForInactive   uint64

	// StakingTrieFrequency represents how many round a staking trie remains
	StakingTrieFrequency uint64
	// MaxDelegationForValidator represents how many delegations a validator can hold
	MaxDelegationForValidator int
	// MaxDelegationForDelegator represents how many delegations a delegator can send
	MaxDelegationForDelegator int
	// MinDelegationTokens is the minimum tokens(in LU) for a single delegation
	MinDelegationTokens *big.Int

	// address of staking module master
	MasterAddress common.Address
}

func (p YouParams) DeepCopy() YouParams {
	cpy := p
	cpy.MinStakes = make(map[ValidatorRole]uint64)
	for key, value := range p.MinStakes {
		cpy.MinStakes[key] = value
	}
	cpy.MaxStakes = make(map[ValidatorRole]uint64)
	for key, value := range p.MaxStakes {
		cpy.MaxStakes[key] = value
	}
	cpy.MinSelfStakes = make(map[ValidatorRole]uint64)
	for key, value := range p.MinSelfStakes {
		cpy.MinSelfStakes[key] = value
	}
	cpy.RewardsDistRatio = make(map[ValidatorRole]uint64)
	for key, value := range p.RewardsDistRatio {
		cpy.RewardsDistRatio[key] = value
	}
	cpy.SignatureRequired = make(map[ValidatorRole]bool)
	for key, value := range p.SignatureRequired {
		cpy.SignatureRequired[key] = value
	}
	cpy.MinDelegationTokens = new(big.Int)
	if p.MinDelegationTokens != nil {
		cpy.MinDelegationTokens.Set(p.MinDelegationTokens)
	}
	return cpy
}
