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
	"errors"
	"fmt"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
)

// protocolRoundBack is used to take a protocol version from previous header.
//
// It's set as constant BECAUSE it's very difficult to use a variable value
// for this purpose.
// It's also difficult to upgrade this constant value
// but yet it is possible when actually needed on some time of the future.
const protocolRoundBack = 8

var (
	errInvalidVersionState = errors.New("invalid version state")
)

// ProcessYouVersionState determines the current protocol state
// from the previous header, and applies it to the current header.
// If there is something wrong, it returns an error.
func ProcessYouVersionState(prev, curr *types.Header) error {
	if prev == nil || curr == nil {
		return errors.New("nil arguments")
	}

	// Find parameters for current protocol;
	prevProto, ok := params.Versions[prev.CurrVersion]
	if !ok {
		return fmt.Errorf("previous protocol %v not supported", prev.CurrVersion)
	}

	upgradeVote := types.UpgradeVote{}
	round := prev.Number.Uint64() + 1
	// If there is no upgrade proposal, see if we can make one
	if prev.NextVersion == 0 {
		if prevProto.ApprovedUpgradeVersion > 0 {
			nextProto, ok := params.Versions[prevProto.ApprovedUpgradeVersion]
			if !ok {
				return fmt.Errorf("approving an upgrade to version %v, but that version does not exists locally", prevProto.ApprovedUpgradeVersion)
			}
			upgradeVote.ProposedVersion = prevProto.ApprovedUpgradeVersion
			if nextProto.UpgradeWaitRounds > prevProto.MinUpgradeWaitRounds {
				if nextProto.UpgradeWaitRounds > prevProto.MaxUpgradeWaitRounds {
					return fmt.Errorf("proposed upgrade wait rounds %d out of permissible range", nextProto.UpgradeWaitRounds)
				}
				upgradeVote.WaitRounds = nextProto.UpgradeWaitRounds
			} else {
				upgradeVote.WaitRounds = prevProto.MinUpgradeWaitRounds
			}
			upgradeVote.UpgradeApprove = true
		}
	} else {
		// If there is a proposal being voted on, see if we approve it and its delay
		if round < prev.NextVoteBefore {
			_, ok := params.Versions[prev.NextVersion]
			upgradeVote.UpgradeApprove = ok
		}
	}

	// apply the version state and upgrade vote
	curr.CurrVersion = prev.CurrVersion
	if upgradeVote.ProposedVersion > 0 {
		// new proposal
		curr.NextVersion = upgradeVote.ProposedVersion
		curr.NextVoteBefore = round + prevProto.UpgradeVoteRounds
		curr.NextSwitchOn = curr.NextVoteBefore + upgradeVote.WaitRounds
		curr.NextApprovals = 1
	} else {
		if prev.NextVersion > 0 {
			// voting an existing upgrade proposal
			// first we copy the version state to current header,
			// and then handle our vote.
			curr.NextVersion = prev.NextVersion
			curr.NextVoteBefore = prev.NextVoteBefore
			curr.NextSwitchOn = prev.NextSwitchOn
			curr.NextApprovals = prev.NextApprovals

			if round < prev.NextVoteBefore {
				if upgradeVote.UpgradeApprove {
					curr.NextApprovals += 1
				}
			}
		}
	}

	// Clear out failed proposal
	if round == curr.NextVoteBefore && curr.NextApprovals < prevProto.UpgradeThreshold {
		clearUpgradeState(curr)
	}

	// Switch over to new approved protocol
	if round == curr.NextSwitchOn {
		curr.CurrVersion = curr.NextVersion
		clearUpgradeState(curr)
	}
	return nil
}

func clearUpgradeState(header *types.Header) {
	header.NextVersion = 0
	header.NextVoteBefore = 0
	header.NextApprovals = 0
	header.NextSwitchOn = 0
}

// VerifyYouVersionState verifies whether the current protocol state
// was upgraded or derived under the rules.
func VerifyYouVersionState(prev, curr *types.Header) (err error) {
	if prev == nil || curr == nil {
		return errors.New("nil arguments")
	}

	// Check parameters of previous header;
	prevProto, ok := params.Versions[prev.CurrVersion]
	if !ok {
		// This should not happen
		logging.Crit("VerifyYouVersionState: previous protocol not supported", "version", prev.CurrVersion)
	}

	currentRound := curr.Number.Uint64()

	// 1. an upgrade
	if prev.NextSwitchOn == currentRound {
		switch {
		case prev.NextVersion != curr.CurrVersion:
			err = errors.New("version not upgrade when demands")
		case curr.NextVersion != 0 || curr.NextVoteBefore != 0 || curr.NextSwitchOn != 0 || curr.NextApprovals != 0:
			err = errors.New("upgrade fields not cleared when version switched")
		}

		if err == nil {
			// check if the client supports the new version
			_, ok := params.Versions[curr.CurrVersion]
			if !ok {
				logging.Crit("YOUChain protocol version not exists, may be you should update the client", "version", curr.CurrVersion)
			}
		}
		return
	}

	isValid := curr.CurrVersion == prev.CurrVersion
	if !isValid {
		return errInvalidVersionState
	}
	// 2. an on-going upgrade proposal
	if prev.NextVersion != 0 {
		if curr.NextVersion == 0 {
			// 2.1 A failure proposal
			isValid = isValid &&
				prev.NextVoteBefore == currentRound &&
				prev.NextApprovals < prevProto.UpgradeThreshold
			isValid = isValid &&
				curr.NextApprovals == 0 &&
				curr.NextVoteBefore == 0 &&
				curr.NextSwitchOn == 0
		} else {
			// 2.2 still on-going
			isValid = isValid && curr.NextVersion == prev.NextVersion
			if curr.NextApprovals < prevProto.UpgradeThreshold {
				isValid = isValid &&
					curr.NextVoteBefore == prev.NextVoteBefore &&
					curr.NextVoteBefore > currentRound
			}
			isValid = isValid &&
				(curr.NextApprovals == prev.NextApprovals ||
					curr.NextApprovals == prev.NextApprovals+1)
			isValid = isValid && curr.NextSwitchOn == prev.NextSwitchOn
		}
	} else {
		if curr.NextVersion != 0 {
			// 3. a new proposal
			isValid = isValid &&
				curr.NextVoteBefore == (currentRound+prevProto.UpgradeVoteRounds) &&
				curr.NextSwitchOn >= (curr.NextVoteBefore+prevProto.MinUpgradeWaitRounds) &&
				curr.NextSwitchOn <= (curr.NextVoteBefore+prevProto.MaxUpgradeWaitRounds) &&
				curr.NextApprovals == 1
		} else {
			// 4. no proposal
			isValid = isValid &&
				curr.NextApprovals == 0 &&
				curr.NextVoteBefore == 0 &&
				curr.NextSwitchOn == 0
		}
	}
	if !isValid {
		return errInvalidVersionState
	}
	return nil
}

func (bc *BlockChain) VerifyYouVersionState(chain types.Blocks) (int, error) {
	firstParent := bc.GetHeaderByNumber(chain[0].NumberU64() - 1)
	if firstParent == nil {
		return 0, consensus.ErrUnknownAncestor
	}

	var err error
	parent := firstParent
	for i, block := range chain {
		curr := block.Header()
		err = VerifyYouVersionState(parent, curr)
		if err != nil {
			return i, err
		}
		parent = curr
	}
	return 0, nil
}

func (bc *BlockChain) VerifyYouVersionState2(chain []*types.Header) (int, error) {
	firstParent := bc.GetHeaderByNumber(chain[0].Number.Uint64() - 1)
	if firstParent == nil {
		return 0, consensus.ErrUnknownAncestor
	}

	var err error
	parent := firstParent
	for i, head := range chain {
		curr := head
		err = VerifyYouVersionState(parent, curr)
		if err != nil {
			return i, err
		}
		parent = curr
	}
	return 0, nil
}

func (bc *BlockChain) VersionForRound(r uint64) (*params.YouParams, error) {
	return bc.hc.VersionForRound(r)
}

func (bc *BlockChain) VersionForRoundWithParents(r uint64, parents []*types.Header) (*params.YouParams, error) {
	return bc.hc.VersionForRoundWithParents(r, parents)
}

func (bc *BlockChain) LookBackVldReaderForRound(r uint64, isCert bool) (state.ValidatorReader, error) {
	yp, err := bc.hc.VersionForRound(r)
	if err != nil {
		return nil, err
	}
	lookBack := uint64(0)
	cfg := yp.StakeLookBack
	if isCert {
		cfg = params.ACoCHTFrequency * 2
	}
	if r > cfg {
		lookBack = r - cfg
	}
	lookBackHeader := bc.GetHeaderByNumber(lookBack)
	if lookBackHeader == nil {
		return nil, fmt.Errorf("header %d not exists", lookBack)
	}
	return bc.GetVldReader(lookBackHeader.ValRoot)
}

func (hc *HeaderChain) VersionForRound(r uint64) (*params.YouParams, error) {
	return hc.VersionForRoundWithParents(r, nil)
}

func (hc *HeaderChain) VersionForRoundWithParents(r uint64, parents []*types.Header) (*params.YouParams, error) {
	var pr uint64
	if r > protocolRoundBack {
		pr = r - protocolRoundBack
	}
	header := hc.GetHeaderByNumber(pr)
	if header == nil {
		if len(parents) > 0 {
			firstNum := parents[0].Number.Uint64()
			if pr >= firstNum {
				header = parents[pr-firstNum]
			}
		}
	}
	if header == nil {
		return nil, fmt.Errorf("can't find header for number %d", pr)
	}

	proto, ok := params.Versions[header.CurrVersion]
	if !ok {
		return nil, fmt.Errorf("protocol version \"%d\" not exist, round %d", header.CurrVersion, pr)
	}
	return &proto, nil
}
