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
	"errors"
	"math/big"

	"github.com/youchainhq/go-youchain/logging"
)

const (
	//Module name of the module
	Module = "staking"

	//logs topic name
	LogTopicCreate         = "create"
	LogTopicUpdate         = "update"
	LogTopicDeposit        = "deposit"
	LogTopicDepositFailed  = "deposit_failed"
	LogTopicWithdraw       = "withdraw"
	LogTopicWithdrawEffect = "withdraw_effect"
	// LogTopicWithdrawResult
	// Topics[1] : operator address
	// data:
	// [0,19]   [20,31]
	// receipt  arrivalAmount
	LogTopicWithdrawResult     = "withdraw_result"
	LogTopicRewards            = "rewards"
	LogTopicSlashing           = "slashing"
	LogTopicChangeStatus       = "change_status"
	LogTopicChangeStatusFailed = "change_status_failed"
	LogTopicSettle             = "settle"

	// topics of pending delegation transaction,
	// the "data" is a combined data as follow:
	// 		[0,8)							[8,32)
	// take-effects-on-which-block-number	final-delegation-tokens-after-the-transaction-take-effects (ignore it for settle)
	LogTopicDelegationPending = "delegation_op_pending"

	LogTopicDelegationAddFailed = "delegation_add_failed"
	LogTopicDelegationSubFailed = "delegation_sub_failed"
	LogTopicDelegationSubEffect = "delegation_sub_effect"

	LogTopicProposerRewards = "proposer_rewards"
)

var (
	log                              = logging.New("mode", Module)
	errHeaderRequired                = errors.New("header required")
	errAuthorizationFailed           = errors.New("authorization failed")
	errNotHouseValidator             = errors.New("not house validator")
	errValidatorIsExpelled           = errors.New("validator has been expelled")
	errValidatorIsOffline            = errors.New("validator is offline")
	errValidatorNotFound             = errors.New("validator not found")
	errRecipientRequired             = errors.New("recipient required")
	errInvalidateMasterSign          = errors.New("invalidate master sign")
	errInvalidateMainPubKey          = errors.New("invalidate mainPubKey")
	errNothingHappened               = errors.New("nothing happened")
	errValidatorAlreadyExist         = errors.New("validator already exist")
	errInsufficientBalanceForDeposit = errors.New("insufficient balance for paying a deposit")
	errInsufficientDeposit           = errors.New("insufficient deposit")
	errInsufficientWithdraw          = errors.New("insufficient staking for withdraw")
	errModuleAddress                 = errors.New("error module address")
	errInsufficientSelfStaking       = errors.New("insufficient self staking")
	errPendingExistForChangeStatus   = errors.New("pending transaction exist, can not change status")
	errInsufficientStakeToOnline     = errors.New("insufficient stake, can not online")
	errStakesOverflow                = errors.New("stakes overflow")

	errNotAcceptDelegation            = errors.New("validator do not accept delegation")
	errSeftDelegating                 = errors.New("can not apply delegation transaction to oneself")
	errDelegationValueTooLow          = errors.New("delegation value too low")
	errInsufficientBalanceForDelegate = errors.New("insufficient balance for delegation")
	errNoMoreDelegationsForValidator  = errors.New("validator can not accepts more delegations from new delegator due to limit")
	errNoMoreDelegationsForDelegator  = errors.New("delegator can not delegates to any new validator due to limit")
	errInsufficientValueForUnbind     = errors.New("insufficient delegation balance for unbind")
	errDelegationNotExist             = errors.New("delegation to validator not exist")

	valNameMaxLength = 42

	//EventTypeDoubleSign type of slashdata
	EventTypeDoubleSign uint8 = 0x0
	//EventTypeInactive type of slashdata
	EventTypeInactive uint8 = 0x1

	inactiveThreshold = 0.2 //todo cal it by formula

	bigZero = big.NewInt(0) //readonly
)
