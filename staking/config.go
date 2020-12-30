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
	Module = "staking" // 0x000000000000000000000000000000000000000000000000007374616b696e67

	//logs topic name
	LogTopicCreate         = "create"          // 0x0000000000000000000000000000000000000000000000000000637265617465
	LogTopicUpdate         = "update"          // 0x0000000000000000000000000000000000000000000000000000757064617465
	LogTopicDeposit        = "deposit"         // 0x000000000000000000000000000000000000000000000000006465706f736974
	LogTopicDepositFailed  = "deposit_failed"  // 0x0000000000000000000000000000000000006465706f7369745f6661696c6564
	LogTopicWithdraw       = "withdraw"        // 0x0000000000000000000000000000000000000000000000007769746864726177
	LogTopicWithdrawEffect = "withdraw_effect" // 0x000000000000000000000000000000000077697468647261775f656666656374
	// LogTopicWithdrawResult
	// Topics[1] : operator address
	// data:
	// [0,19]   [20,31]
	// receipt  arrivalAmount
	LogTopicWithdrawResult     = "withdraw_result"      // 0x000000000000000000000000000000000077697468647261775f726573756c74
	LogTopicRewards            = "rewards"              // 0x0000000000000000000000000000000000000000000000000072657761726473
	LogTopicSlashing           = "slashing"             // 0x000000000000000000000000000000000000000000000000736c617368696e67
	LogTopicChangeStatus       = "change_status"        // 0x000000000000000000000000000000000000006368616e67655f737461747573
	LogTopicChangeStatusFailed = "change_status_failed" // 0x0000000000000000000000006368616e67655f7374617475735f6661696c6564
	LogTopicSettle             = "settle"               // 0x0000000000000000000000000000000000000000000000000000736574746c65

	// topics of pending delegation transaction,
	// the "data" is a combined data as follow:
	// 		[0,8)							[8,32)
	// take-effects-on-which-block-number	final-delegation-tokens-after-the-transaction-take-effects (ignore it for settle)
	LogTopicDelegationPending = "delegation_op_pending" // 0x000000000000000000000064656c65676174696f6e5f6f705f70656e64696e67

	LogTopicDelegationAddFailed = "delegation_add_failed" // 0x000000000000000000000064656c65676174696f6e5f6164645f6661696c6564
	LogTopicDelegationSubFailed = "delegation_sub_failed" // 0x000000000000000000000064656c65676174696f6e5f7375625f6661696c6564
	LogTopicDelegationSubEffect = "delegation_sub_effect" // 0x000000000000000000000064656c65676174696f6e5f7375625f656666656374

	LogTopicProposerRewards = "proposer_rewards" // 0x0000000000000000000000000000000070726f706f7365725f72657761726473
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
