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

package core

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/params"
	"math/big"
	"testing"
)

func init() {
	params.InitNetworkId(params.NetworkIdForTestCase)
}

func TestVerifyYouVersionState(t *testing.T) {
	type tcS struct {
		prev, curr  *types.Header
		wantNoError bool
		wantErr     error
	}
	yp, ok := params.Versions[params.YouCurrentVersion]
	require.True(t, ok)

	tcs := []tcS{
		//no proposal
		{
			prev: &types.Header{
				Number:         big.NewInt(0),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			curr: &types.Header{
				Number:         big.NewInt(1),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			wantNoError: true,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(0),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			curr: &types.Header{
				Number:         big.NewInt(1),
				CurrVersion:    params.YouVersion(2),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			wantErr: errInvalidVersionState,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(0),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			curr: &types.Header{
				Number:         big.NewInt(1),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  1,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			wantErr: errInvalidVersionState,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(0),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			curr: &types.Header{
				Number:         big.NewInt(1),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 1,
				NextSwitchOn:   0,
			},
			wantErr: errInvalidVersionState,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(0),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			curr: &types.Header{
				Number:         big.NewInt(1),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   1,
			},
			wantErr: errInvalidVersionState,
		},
		//new proposal
		{
			prev: &types.Header{
				Number:         big.NewInt(1000),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			curr: &types.Header{
				Number:         big.NewInt(1001),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  1,
				NextVoteBefore: 1001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1001 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			wantNoError: true,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(1000),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			curr: &types.Header{
				Number:         big.NewInt(1001),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  1,
				NextVoteBefore: 1001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1001 + yp.UpgradeVoteRounds + yp.MaxUpgradeWaitRounds,
			},
			wantNoError: true,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(1000),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			curr: &types.Header{
				Number:         big.NewInt(1001),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(3),
				NextApprovals:  1,
				NextVoteBefore: 1001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1001 + yp.UpgradeVoteRounds + yp.MaxUpgradeWaitRounds,
			},
			wantNoError: true,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(1000),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			curr: &types.Header{
				Number:         big.NewInt(1001),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  0,
				NextVoteBefore: 1001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1001 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			wantErr: errInvalidVersionState,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(1000),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			curr: &types.Header{
				Number:         big.NewInt(1001),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  10,
				NextVoteBefore: 1001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1001 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			wantErr: errInvalidVersionState,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(1000),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			curr: &types.Header{
				Number:         big.NewInt(1001),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  1,
				NextVoteBefore: 1001 + yp.UpgradeVoteRounds - 1,
				NextSwitchOn:   1001 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			wantErr: errInvalidVersionState,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(1000),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			curr: &types.Header{
				Number:         big.NewInt(1001),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  1,
				NextVoteBefore: 1001 + yp.UpgradeVoteRounds + 1,
				NextSwitchOn:   1001 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			wantErr: errInvalidVersionState,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(1000),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			curr: &types.Header{
				Number:         big.NewInt(1001),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  1,
				NextVoteBefore: 1001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1001 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds - 1,
			},
			wantErr: errInvalidVersionState,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(1000),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			curr: &types.Header{
				Number:         big.NewInt(1001),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  1,
				NextVoteBefore: 1001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1001 + yp.UpgradeVoteRounds + yp.MaxUpgradeWaitRounds + 1,
			},
			wantErr: errInvalidVersionState,
		},
		// on-going proposal
		{
			prev: &types.Header{
				Number:         big.NewInt(10000),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  1,
				NextVoteBefore: 10001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   10001 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			curr: &types.Header{
				Number:         big.NewInt(10001),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  1,
				NextVoteBefore: 10001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   10001 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			wantNoError: true,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(10000),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  1,
				NextVoteBefore: 10001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   10001 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			curr: &types.Header{
				Number:         big.NewInt(10001),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  2,
				NextVoteBefore: 10001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   10001 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			wantNoError: true,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(10000),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  1,
				NextVoteBefore: 10001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   10001 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			curr: &types.Header{
				Number:         big.NewInt(10001),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  3,
				NextVoteBefore: 10001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   10001 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			wantErr: errInvalidVersionState,
		},
		{
			prev: &types.Header{
				Number:         big.NewInt(10000),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  10,
				NextVoteBefore: 10001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   10001 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			curr: &types.Header{
				Number:         big.NewInt(10001),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  9,
				NextVoteBefore: 10001 + yp.UpgradeVoteRounds,
				NextSwitchOn:   10001 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			wantErr: errInvalidVersionState,
		},
		// failed proposal
		{
			prev: &types.Header{
				Number:         new(big.Int).SetUint64(yp.UpgradeVoteRounds),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  yp.UpgradeThreshold - 2,
				NextVoteBefore: 1 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			curr: &types.Header{
				Number:         new(big.Int).SetUint64(1 + yp.UpgradeVoteRounds),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			wantNoError: true,
		},
		{
			prev: &types.Header{
				Number:         new(big.Int).SetUint64(yp.UpgradeVoteRounds),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  yp.UpgradeThreshold - 2,
				NextVoteBefore: 1 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			curr: &types.Header{
				Number:         new(big.Int).SetUint64(1 + yp.UpgradeVoteRounds),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  yp.UpgradeThreshold - 1,
				NextVoteBefore: 1 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			wantErr: errInvalidVersionState,
		},
		// succeed proposal
		{
			prev: &types.Header{
				Number:         new(big.Int).SetUint64(yp.UpgradeVoteRounds),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  yp.UpgradeThreshold,
				NextVoteBefore: 1 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			curr: &types.Header{
				Number:         new(big.Int).SetUint64(1 + yp.UpgradeVoteRounds),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  yp.UpgradeThreshold,
				NextVoteBefore: 1 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			wantNoError: true,
		},
		{
			prev: &types.Header{
				Number:         new(big.Int).SetUint64(yp.UpgradeVoteRounds),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  yp.UpgradeThreshold,
				NextVoteBefore: 1 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			curr: &types.Header{
				Number:         new(big.Int).SetUint64(1 + yp.UpgradeVoteRounds),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			wantErr: errInvalidVersionState,
		},
		// switch on
		{
			prev: &types.Header{
				Number:         new(big.Int).SetUint64(yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  yp.UpgradeThreshold,
				NextVoteBefore: 1 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			curr: &types.Header{
				Number:         new(big.Int).SetUint64(1 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    0,
				NextApprovals:  0,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			wantNoError: false,
		},
		{
			prev: &types.Header{
				Number:         new(big.Int).SetUint64(yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds),
				CurrVersion:    params.YouVersion(1),
				NextVersion:    params.YouVersion(2),
				NextApprovals:  yp.UpgradeThreshold,
				NextVoteBefore: 1 + yp.UpgradeVoteRounds,
				NextSwitchOn:   1 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds,
			},
			curr: &types.Header{
				Number:         new(big.Int).SetUint64(1 + yp.UpgradeVoteRounds + yp.MinUpgradeWaitRounds),
				CurrVersion:    params.YouVersion(2),
				NextVersion:    params.YouVersion(3),
				NextApprovals:  1,
				NextVoteBefore: 0,
				NextSwitchOn:   0,
			},
			wantNoError: false,
		},
	}

	fmt.Printf("total testCase : %d\n", len(tcs))

	for i, tc := range tcs {
		err := VerifyYouVersionState(tc.prev, tc.curr)
		if tc.wantNoError {
			assert.NoError(t, err, fmt.Sprintf("testCaseIndex: %d", i))
		}
		if tc.wantErr != nil {
			assert.Equal(t, tc.wantErr, err, fmt.Sprintf("testCaseIndex: %d", i))
		}
	}
}
