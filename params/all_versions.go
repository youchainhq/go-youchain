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
	"time"
)

const (
	EvmIstanbul = "Istanbul"
)

type VersionsMap map[YouVersion]YouParams

// Versions contains all YOUChain protocol version and it's parameters
var Versions VersionsMap

//
var minStakeLookBack = 128

// MinStakeLookBack returns a minimal stakeLookBack value,
// It can be used for concurrency control when batch handling headers or blocks.
func MinStakeLookBack() int {
	return minStakeLookBack
}

func initConsensusProtocols(networkId uint64) {
	switch networkId {
	case MainNetId:
		Versions = mainNetProtocols()
	case TestNetId:
		Versions = testNetProtocols()
	case NetworkIdForTestCase:
		Versions = protocolsForTestCase()
	default:
		//other networkid ->private net, use testnet version config
		Versions = testNetProtocols()
	}

	var seedLookBack uint64
	for _, v := range Versions {
		if v.StakeLookBack < uint64(minStakeLookBack) {
			minStakeLookBack = int(v.StakeLookBack)
		}

		// Currently the downloader do not support different seedLookBack value
		// If it's needed to set different seedLookBack for different versions,
		// then we should add support for the downloader, and then remove the follow logic.
		if seedLookBack == 0 {
			seedLookBack = v.SeedLookBack
		} else {
			if seedLookBack != v.SeedLookBack {
				panic("Make sure the Downloader supports different seedLookBack and then remove this logic.")
			}
		}
	}
}

func mainNetProtocols() VersionsMap {
	versionMap := make(VersionsMap)
	// WARNING: copying a YouParams by value into a new variable
	// does not copy any reference objects.  Make sure that each new
	// YouParams structure gets a fresh new object.
	// That is: MUST do a deep copy.

	v1 := YouParams{
		Version:    YouV1,
		EVMVersion: EvmIstanbul,
		CaravelParams: CaravelParams{
			ProposerThreshold:     26,
			ValidatorThreshold:    2000,
			CertValThreshold:      4000,
			ConsensusTimeout:      10000 * time.Millisecond,
			ConsensusStepInterval: 2000 * time.Millisecond,
			StakeLookBack:         128,
			SeedLookBack:          8,
			EnableBls:             true,
			EnableInactivity:      false,

			AllowedFutureBlockTime: 15 * time.Second,
		},
		StakingParams: StakingParams{
			RewardsPoolAddress: common.BigToAddress(big.NewInt(0x0000000000000000000000000000001111111111)),
			SubsidyThreshold:   9 * YOU,
			SubsidyCoeff:       5,
			SignatureRequired: map[ValidatorRole]bool{
				RoleChancellor: true,
				RoleSenator:    true,
				RoleHouse:      true,
			},
			MinStakes: map[ValidatorRole]uint64{
				RoleChancellor: 8880000,
				RoleSenator:    1580000,
				RoleHouse:      49283,
			},
			MaxStakes: map[ValidatorRole]uint64{
				RoleChancellor: 10000000,
				RoleSenator:    1800000,
				RoleHouse:      1500000,
			},
			MinSelfStakes: map[ValidatorRole]uint64{
				RoleChancellor: 0,
				RoleSenator:    0,
				RoleHouse:      0,
			},
			RewardsDistRatio: map[ValidatorRole]uint64{
				RoleChancellor: 3,
				RoleSenator:    3,
				RoleHouse:      4,
			},

			MaxRewardsPeriod:     128,
			MaxEvidenceExpiredIn: 120,

			WithdrawDelay:           259200, // 15 days
			WithdrawRecordRetention: 1440,   // 2 hours

			ExpelledRoundForDoubleSign: 518400, // 30 days
			ExpelledRoundForInactive:   1440,   // 2 hours

			PenaltyTo:                    common.BigToAddress(big.NewInt(0x0000000000000000000000000000001111111112)),
			PenaltyFractionForDoubleSign: 2,
			PenaltyFractionForInactive:   1,

			StakingTrieFrequency:      128,
			MaxDelegationForValidator: 2000,
			MaxDelegationForDelegator: 128,
			MinDelegationTokens:       new(big.Int).Mul(big.NewInt(1000), StakeUint),

			MasterAddress: common.HexToAddress("0xBEC0C4669E0bF1dAbc25d3B410C38da1f6Be73a9"),
		},

		UpgradeVoteRounds:    10000,
		UpgradeThreshold:     9000,
		MinUpgradeWaitRounds: 10000,
		MaxUpgradeWaitRounds: 15000,
	}

	// v1 can updates to v2
	v2 := v1.DeepCopy() // copy first
	// then update v1
	v1.ApprovedUpgradeVersion = YouV2
	// update the map value.
	// then the previous `versionMap[v1.Version] = v1` can be deleted
	versionMap[v1.Version] = v1

	// change, set v2 values
	v2.Version = YouV2
	//Add or modify some params
	v2.AllowedFutureBlockTime = 10 * time.Second // use a smaller duration according to consensus time.
	versionMap[v2.Version] = v2

	return versionMap
}

func testNetProtocols() VersionsMap {
	versionMap := make(VersionsMap)
	// WARNING: copying a YouParams by value into a new variable
	// does not copy any reference objects.  Make sure that each new
	// YouParams structure gets a fresh new object.
	// That is: MUST do a deep copy.

	v1 := YouParams{
		Version:    YouV1,
		EVMVersion: EvmIstanbul,
		CaravelParams: CaravelParams{
			ProposerThreshold:     26,
			ValidatorThreshold:    2000,
			CertValThreshold:      4000,
			ConsensusTimeout:      3000 * time.Millisecond,
			ConsensusStepInterval: 500 * time.Millisecond,
			StakeLookBack:         128,
			SeedLookBack:          8,
			EnableBls:             true,
			EnableInactivity:      false,

			AllowedFutureBlockTime: 15 * time.Second,
		},
		StakingParams: StakingParams{
			RewardsPoolAddress: common.BigToAddress(big.NewInt(0x0000000000000000000000000000001111111111)),
			SubsidyThreshold:   9 * YOU,
			SubsidyCoeff:       5,
			SignatureRequired: map[ValidatorRole]bool{
				RoleChancellor: true,
				RoleSenator:    true,
				RoleHouse:      true,
			},
			MinStakes: map[ValidatorRole]uint64{
				RoleChancellor: 1000,
				RoleSenator:    500,
				RoleHouse:      100,
			},
			MaxStakes: map[ValidatorRole]uint64{
				RoleChancellor: 10000000,
				RoleSenator:    1800000,
				RoleHouse:      1500000,
			},
			MinSelfStakes: map[ValidatorRole]uint64{
				RoleChancellor: 0,
				RoleSenator:    0,
				RoleHouse:      0,
			},
			RewardsDistRatio: map[ValidatorRole]uint64{
				RoleChancellor: 3,
				RoleSenator:    3,
				RoleHouse:      4,
			},

			MaxRewardsPeriod:     10,
			MaxEvidenceExpiredIn: 120,

			WithdrawDelay:           20,
			WithdrawRecordRetention: 100,

			ExpelledRoundForDoubleSign: 512,
			ExpelledRoundForInactive:   128,

			PenaltyTo:                    common.BigToAddress(big.NewInt(0x0000000000000000000000000000001111111112)),
			PenaltyFractionForDoubleSign: 2,
			PenaltyFractionForInactive:   1,

			StakingTrieFrequency:      8,
			MaxDelegationForValidator: 20,
			MaxDelegationForDelegator: 20,
			MinDelegationTokens:       new(big.Int).Mul(big.NewInt(10), StakeUint),

			MasterAddress: common.HexToAddress("0x35049C793fd29605CdDcFc896620A4522b6f7496"),
		},

		UpgradeVoteRounds:    10000,
		UpgradeThreshold:     9000,
		MinUpgradeWaitRounds: 10000,
		MaxUpgradeWaitRounds: 15000,
	}

	// v1 can updates to v2
	v2 := v1.DeepCopy() // copy first
	// then update v1
	v1.ApprovedUpgradeVersion = YouV2
	// update the map value.
	// then the previous `versionMap[v1.Version] = v1` can be deleted
	versionMap[v1.Version] = v1

	// change, set v2 values
	v2.Version = YouV2
	//Add or modify some params
	v2.AllowedFutureBlockTime = 10 * time.Second // use a smaller duration according to consensus time.
	versionMap[v2.Version] = v2

	return versionMap
}

func protocolsForTestCase() VersionsMap {
	versionMap := make(VersionsMap)
	// WARNING: copying a YouParams by value into a new variable
	// does not copy any reference objects.  Make sure that each new
	// YouParams structure gets a fresh new object.
	// That is: MUST do a deep copy.

	v1 := YouParams{
		Version:    YouV1,
		EVMVersion: EvmIstanbul,
		CaravelParams: CaravelParams{
			ProposerThreshold:     26,
			ValidatorThreshold:    2000,
			CertValThreshold:      4000,
			ConsensusTimeout:      3000 * time.Millisecond,
			ConsensusStepInterval: 500 * time.Millisecond,
			StakeLookBack:         64,
			SeedLookBack:          8,
			EnableBls:             true,
			EnableInactivity:      false,

			AllowedFutureBlockTime: 15 * time.Second,
		},
		StakingParams: StakingParams{
			RewardsPoolAddress: common.BigToAddress(big.NewInt(0x0000000000000000000000000000001111111111)),
			SubsidyThreshold:   9 * YOU,
			SubsidyCoeff:       5,
			SignatureRequired: map[ValidatorRole]bool{
				RoleChancellor: true,
				RoleSenator:    true,
				RoleHouse:      true,
			},
			MinStakes: map[ValidatorRole]uint64{
				RoleChancellor: 1000,
				RoleSenator:    500,
				RoleHouse:      100,
			},
			MaxStakes: map[ValidatorRole]uint64{
				RoleChancellor: 1000000,
				RoleSenator:    180000,
				RoleHouse:      150000,
			},
			MinSelfStakes: map[ValidatorRole]uint64{
				RoleChancellor: 0,
				RoleSenator:    0,
				RoleHouse:      0,
			},
			RewardsDistRatio: map[ValidatorRole]uint64{
				RoleChancellor: 3,
				RoleSenator:    3,
				RoleHouse:      4,
			},

			MaxRewardsPeriod:     128,
			MaxEvidenceExpiredIn: 120,

			WithdrawDelay:           96,
			WithdrawRecordRetention: 128,

			ExpelledRoundForDoubleSign: 256,
			ExpelledRoundForInactive:   64,

			PenaltyTo:                    common.BigToAddress(big.NewInt(0x0000000000000000000000000000001111111112)),
			PenaltyFractionForDoubleSign: 2,
			PenaltyFractionForInactive:   1,

			StakingTrieFrequency:      128,
			MaxDelegationForValidator: 2000,
			MaxDelegationForDelegator: 128,
			MinDelegationTokens:       new(big.Int).Mul(big.NewInt(10), StakeUint),

			MasterAddress: common.HexToAddress("0x35049C793fd29605CdDcFc896620A4522b6f7496"),
		},

		UpgradeVoteRounds:    1000,
		UpgradeThreshold:     900,
		MinUpgradeWaitRounds: 1000,
		MaxUpgradeWaitRounds: 1500,
	}

	// v1 can updates to v2
	v2 := v1.DeepCopy() // copy first
	// then update v1
	v1.ApprovedUpgradeVersion = YouV2
	// update the map value.
	// then the previous `versionMap[v1.Version] = v1` can be deleted
	versionMap[v1.Version] = v1

	// change, set v2 values
	v2.Version = YouV2
	//Add or modify some params
	v2.AllowedFutureBlockTime = 10 * time.Second // use a smaller duration according to consensus time.
	versionMap[v2.Version] = v2

	return versionMap
}
