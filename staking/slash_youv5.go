/*
 * Copyright 2020 YOUCHAIN FOUNDATION LTD.
 * This file is part of the go-youchain library.
 *
 * The go-youchain library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The go-youchain library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the go-youchain library. If not, see <http://www.gnu.org/licenses/>.
 */

package staking

import (
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rlp"
	"math/big"
)

func inactivitySlashingYouV5(ctx *context) {
	if ctx.header.CurrVersion < params.YouV5 {
		return
	}

	num := ctx.header.Number.Uint64()
	waitRounds := ctx.config.InactivityPenaltyWaitRounds
	all := ctx.db.GetValidatorsForUpdate()
	for _, val := range all {
		if val.Role == params.RoleHouse || val.IsOffline() {
			continue
		}
		if num-val.LastActive() <= waitRounds {
			continue
		}

		old := val.PartialCopy()
		logData := SlashDataV5{
			Type:        EventTypeInactive,
			MainAddress: val.MainAddress(),
		}
		// inactive
		if ctx.config.PenaltyFractionForInactive > 0 {
			penaltyAmount := new(big.Int).Div(new(big.Int).Mul(val.Token, big.NewInt(int64(ctx.config.PenaltyFractionForInactive))), big.NewInt(100))
			logData.Total, logData.FromWithdraw, logData.FromDeposit = doPenalize(ctx.config, EvidenceTypeInactive, ctx.db, ctx.header, val, penaltyAmount, num)
		}
		val.Status = params.ValidatorOffline
		val.Expelled = true
		expelExpired := num + ctx.config.ExpelledRoundForInactive
		if expelExpired > val.ExpelExpired {
			val.ExpelExpired = expelExpired
		}
		ctx.db.UpdateValidator(val, old)
		// receipt
		rlpData, err := rlp.EncodeToBytes(logData)
		if err != nil {
			log.Error("rlp encode SlashDataV5 failed", "err", err)
			continue
		}
		ctx.receipt.Logs = append(ctx.receipt.Logs, &types.Log{
			Address:     params.StakingModuleAddress,
			Topics:      []common.Hash{common.StringToHash(LogTopicSlashing)},
			Data:        rlpData,
			BlockNumber: num,
		})
	}
}
