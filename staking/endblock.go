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
	"math/big"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/common/hexutil"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/rawdb"
	"github.com/youchainhq/go-youchain/core/state"
	"github.com/youchainhq/go-youchain/core/types"
	"github.com/youchainhq/go-youchain/core/vm"
	"github.com/youchainhq/go-youchain/local"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
)

// tempRewardsRecord is a struct used on handling rewards.
type tempRewardsRecord struct {
	total, per, residue *big.Int
}

type context struct {
	chain    vm.ChainReader
	config   *params.YouParams
	db       *state.StateDB
	header   *types.Header
	receipt  *types.Receipt
	recorder local.DetailRecorder
}

//EndBlock process slashing and rewarding for block
func EndBlock(staking *Staking) core.BlockHookFn {
	return func(chain vm.ChainReader, header *types.Header, txs []*types.Transaction, db *state.StateDB, isSeal bool, recorder local.DetailRecorder) (*types.Receipt, []byte, error) {
		if header == nil {
			return nil, nil, errHeaderRequired
		}
		var err error
		startAt := time.Now()
		blockTime := header.Time
		log.Trace("endblock start", "current", chain.CurrentHeader().Number, "sealing", header.Number,
			"isSeal", isSeal, "blockTime", blockTime, "start", startAt.UnixNano(), "slashdata", hexutil.Encode(header.SlashData))
		defer func() {
			logFn := log.Trace
			if err != nil {
				logFn = log.Error
			}
			logFn("endblock finished", "current", chain.CurrentHeader().Number, "sealing", header.Number,
				"elapsed", time.Since(startAt), "slashdata", hexutil.Encode(header.SlashData), "err", err)
		}()

		receipt := types.NewReceipt([]byte{}, false, header.GasUsed)

		// current You parameters
		currConfig, err := chain.VersionForRound(header.Number.Uint64())
		if err != nil {
			return nil, nil, fmt.Errorf("find YouVersion parameters error: %v", err)
		}
		ctx := &context{
			chain:    chain,
			config:   currConfig,
			db:       db,
			header:   header,
			receipt:  receipt,
			recorder: recorder,
		}

		checkAndUpgradeValidatorsToYouV5(ctx)

		// slashing
		if isSeal {
			if _, _, _, err = staking.slashing(ctx); err != nil {
				log.Error("slashing", "height", header.Number, "err", err)
			}
		} else {
			if _, _, _, err = staking.replaySlashing(ctx); err != nil {
				log.Error("replaySlashing", "height", header.Number, "err", err)
			}
		}

		// rewards to pool for each block
		rewardsToPool(ctx)

		// process the staking business on the end of a period
		if err = staking.endStakingPeriod(ctx, txs); err != nil {
			log.Error("endStakingPeriod failed", "height", header.Number, "err", err)
		}

		// finally, complete the module receipt (none-transaction-related)
		receipt.ContractAddress = params.StakingModuleAddress
		receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
		receipt.BlockHash = db.BlockHash()
		receipt.BlockNumber = new(big.Int).Set(header.Number)
		receipt.TransactionIndex = uint(db.TxIndex())

		return receipt, nil, nil
	}
}

// checkAndUpgradeValidatorsToYouV5 initializes the lastProposed value of each validator on the first block of YouV5,
// so it can be used for inactivity check.
func checkAndUpgradeValidatorsToYouV5(ctx *context) {
	if ctx.header.CurrVersion != params.YouV5 {
		return
	}

	num := ctx.header.Number.Uint64()
	parent := ctx.chain.GetHeader(ctx.header.ParentHash, num-1)
	if parent.CurrVersion == params.YouV4 {
		logging.Info("update current validators to YouV5", "height", num)
		// only do once on the first YouV5 block.
		all := ctx.db.GetValidatorsForUpdate()
		for _, val := range all {
			if val.Role != params.RoleHouse && val.IsOnline() {
				old := val.PartialCopy()
				val.UpdateLastActive(num)
				ctx.db.UpdateValidator(val, old)
				logging.Info("update current validator to YouV5", "mainAddr", val.MainAddress(), "role", val.Role)
			}
		}
	}
}

func rewardsToPool(ctx *context) {
	initStat, _ := ctx.db.GetValidatorsStat()
	blockRewards := blockRewards(ctx.config, ctx.db, ctx.header, initStat.GetRewardResidue())
	if blockRewards.Sign() <= 0 {
		// no rewards, just return
		return
	}

	// calculates the rewards of each role,
	// only to the role which has online validators.
	type rewardsInfo struct {
		ratio   uint64
		rewards *big.Int
	}
	roleRewards := make(map[params.ValidatorRole]*rewardsInfo)
	var sumOfPortions uint64
	for _, role := range []params.ValidatorRole{params.RoleChancellor, params.RoleSenator, params.RoleHouse} {
		if initStat.GetByRole(role).GetCount() > 0 {
			r := ctx.config.RewardsDistRatio[role]
			roleRewards[role] = &rewardsInfo{
				ratio:   r,
				rewards: new(big.Int),
			}
			sumOfPortions += r
		}
	}

	rewardsPerPortion := new(big.Int)
	residue := new(big.Int)
	rewardsPerPortion.QuoRem(blockRewards, new(big.Int).SetUint64(sumOfPortions), residue)

	for _, info := range roleRewards {
		info.rewards.Mul(rewardsPerPortion, new(big.Int).SetUint64(info.ratio))
	}

	// distributes the rewards to block-proposer and the pools of other role of validators
	proposer := ctx.db.GetValidatorByMainAddr(ctx.header.Coinbase)
	if proposer == nil {
		// an validator is removed from validators set only when its total staking is zero,
		// and there's a WithdrawDelay when it do a withdraw, and the WithdrawDelay MUST greater then the StakeLookBack,
		// so, the proposer MUST exist.
		logging.Crit("SHOULD NOT HAPPENED. proposer not in the current validators set", "blockNumber", ctx.header.Number, "coinbase", ctx.header.Coinbase.String())
	}

	// starting from YouProtocol version V5, the proposer will get all rewards for chambers.
	proposerReward := new(big.Int)
	oldVal := proposer.PartialCopy()
	if ctx.header.CurrVersion >= params.YouV5 {
		for role, info := range roleRewards {
			if role == params.RoleHouse {
				initStat.GetByRole(role).AddRewards(info.rewards)
			} else {
				proposerReward.Add(proposerReward, info.rewards)
			}
		}
		proposer.UpdateLastActive(ctx.header.Number.Uint64())
	} else {
		for role, info := range roleRewards {
			if role == proposer.Role {
				// proposer got the whole rewards of its role
				proposerReward.Add(proposerReward, info.rewards)
			} else {
				// add to role stat's pool
				initStat.GetByRole(role).AddRewards(info.rewards)
			}
		}
	}
	// updates proposer's reward
	proposer.AddTotalRewards(proposerReward)
	ctx.db.UpdateValidator(proposer, oldVal)
	ctx.receipt.Logs = append(ctx.receipt.Logs, &types.Log{
		Address:     params.StakingModuleAddress,
		Topics:      []common.Hash{common.StringToHash(LogTopicProposerRewards), proposer.MainAddress().Hash()},
		Data:        common.BigToHash(proposerReward).Bytes(),
		BlockNumber: ctx.header.Number.Uint64(),
	})

	// collect the global residue
	initStat.GetByKind(params.KindValidator).SetRewardsResidue(residue)
}

func (s *Staking) endStakingPeriod(ctx *context, txs []*types.Transaction) (err error) {
	blockNumber := ctx.header.Number.Uint64()
	if (blockNumber+1)%ctx.config.StakingTrieFrequency != 0 {
		// not the end of a staking period
		return nil
	}

	// YouV5 inactivity slashing (only for chamber validators)
	inactivitySlashingYouV5(ctx)

	// distributes rewards to each account
	var settled map[common.Address]struct{}
	if settled, err = s.distributeRewards(ctx); err != nil {
		return fmt.Errorf("handleRewards failed, err=%v ", err)
	}

	// process current withdraw queue
	processWithdrawQueue(ctx)

	// make all pending staking transactions of current period to take effects.
	err = processPendingTxs(ctx, txs, settled)

	return err
}

// distributeRewards distributes rewards to each validator on the end of a staking period.
// It also try to settle validator rewards for those without settled for a time longer then the interval by config.
func (s *Staking) distributeRewards(ctx *context) (map[common.Address]struct{}, error) {
	// settle rewards before validators updating
	initStat, _ := ctx.db.GetValidatorsStat()

	if initStat.GetStakeByKind(params.KindValidator).Sign() <= 0 {
		return nil, fmt.Errorf("empty stake")
	}

	// rewards to validators, handle role by role.
	// There are two rules:
	// 1. for Chancellor and Senator, distributes by stakes;
	// 2. for House, distributes just by equal.
	// Besides, only distribute rewards to online validators.
	//
	// Also note that:
	// we will try to settle rewards ( to each delegator under the validator)
	// for those who is offline or without settled for a long time.
	//
	// Well, another note: Settle rewards will also be done immediately before a validator
	// got any transaction need to take effects, and this logic is under the `processPendingTxs`.

	// map for recording rewards data
	rewardsRecord := make(map[params.ValidatorRole]*tempRewardsRecord)
	// Calculates rewards per-stake or per-validator by statistics data.
	// Note: it's less precise but has higher performance.
	// and because the reward is in unit of LU, it's very likely that it will much more greater then Stake (which is in YOU),
	// so the precise will be acceptable.
	for _, role := range []params.ValidatorRole{params.RoleChancellor, params.RoleSenator, params.RoleHouse} {
		stat := initStat.GetByRole(role)
		if stat.GetCount() == 0 {
			// skip it if no online validators
			continue
		}
		record := &tempRewardsRecord{}
		record.total = stat.GetRewardsDistributable()
		var count *big.Int
		if role == params.RoleHouse {
			count = new(big.Int).SetUint64(stat.GetCount())
		} else {
			count = stat.GetOnlineStake()
		}
		record.per, record.residue = new(big.Int).QuoRem(record.total, count, new(big.Int))
		rewardsRecord[role] = record
	}

	settled := make(map[common.Address]struct{}) // map for recording validators have been forced to settle rewards.
	currRound := ctx.header.Number.Uint64()
	forceSettleGap := ctx.config.MaxRewardsPeriod * ctx.config.StakingTrieFrequency
	// do distribute
	var allValidators []*state.Validator
	if ctx.header.CurrVersion >= params.YouV5 {
		allValidators = ctx.db.GetValidatorsForUpdate()
	} else {
		allValidators = ctx.db.GetValidators().List()
	}
	for _, val := range allValidators {
		if val.IsOffline() {
			settleValidatorRewards(ctx, val, currRound)
			settled[val.MainAddress()] = struct{}{}
			continue
		}

		record := rewardsRecord[val.Role]
		rewards := record.per
		if val.Role != params.RoleHouse {
			rewards = new(big.Int).Mul(record.per, val.Stake)
		}
		record.total.Sub(record.total, rewards)
		if record.total.Sign() < 0 {
			// MUST NOT HAPPEN
			// If it DO HAPPENS, it MUST BE a bug, so log Crit for debug.
			stat := initStat.GetByRole(val.Role)
			var count *big.Int
			if val.Role == params.RoleHouse {
				count = new(big.Int).SetUint64(stat.GetCount())
			} else {
				count = stat.GetOnlineStake()
			}
			logging.Crit("not enough rewards to distribute, it MUST BE a BUG", "role", val.Role, "totalRewards", stat.GetRewardsDistributable(), "per", record.per, "distCount", count, "expectResidue", record.residue, "gotRemains", record.total)
		}
		newVal := val.PartialCopy()
		newVal.AddTotalRewards(rewards)
		ctx.db.UpdateValidator(newVal, val)

		// check if need to settle
		if val.RewardsLastSettled < currRound && val.RewardsLastSettled+forceSettleGap <= currRound {
			settleValidatorRewards(ctx, val, currRound)
			settled[val.MainAddress()] = struct{}{}
		}
	}

	// finally check and save residue
	for role, record := range rewardsRecord {
		stat := initStat.GetByRole(role)
		if record.total.Cmp(record.residue) != 0 {
			// MUST NOT HAPPEN
			// If it DO HAPPENS, it MUST BE a bug, so log Crit for debug.
			var count *big.Int
			if role == params.RoleHouse {
				count = new(big.Int).SetUint64(stat.GetCount())
			} else {
				count = stat.GetOnlineStake()
			}
			logging.Crit("wrong residue, it MUST BE a BUG", "role", role, "totalRewards", stat.GetRewardsDistributable(), "per", record.per, "distCount", count, "expectResidue", record.residue, "gotRemains", record.total)
		}
		stat.ResetRewards(record.residue)
	}

	return settled, nil
}

func processPendingTxs(ctx *context, txs []*types.Transaction, forceSettled map[common.Address]struct{}) error {
	// cache validator address who's rewards has been fully settled
	rewardsSettled := forceSettled

	signer := types.MakeSigner(nil)
	diskDb := ctx.db.Database().TrieDB().DiskDB()
	currRound := ctx.header.Number.Uint64()

	err := ctx.db.ForEachStakingRecord(func(d, v common.Address, record *state.Record) error {
		// As long as any transaction related to a validator, then settle its rewards first.
		if _, settled := rewardsSettled[v]; !settled {
			val := ctx.db.GetValidatorByMainAddr(v)
			// If the pending tx is validatorCreate, then the validator will not exist currently.
			if val != nil {
				settleValidatorRewards(ctx, val, currRound)
			}
			rewardsSettled[v] = struct{}{}
		}
		//take effect the pending transactions
		for _, txHash := range record.TxHashes {
			tx, _, _, _ := rawdb.ReadTransaction(diskDb, txHash)
			if tx == nil {
				for _, t := range txs {
					if t.Hash() == txHash {
						tx = t
						logging.Debug("a current block transaction", "txHash", txHash.String())
						break
					}
				}
				if tx == nil {
					logging.Error("SHOULD NOT HAPPEN. tx not exist", "txHash", txHash.String())
					return fmt.Errorf("tx not exist, txHash=%s", txHash.String())
				}
			}
			msg, _ := tx.AsMessage(signer)
			ctx := &messageContext{
				Msg:     msg,
				State:   ctx.db,
				Cfg:     ctx.config,
				Header:  ctx.header,
				Receipt: ctx.receipt,
			}
			takeEffectEntry(ctx)
		}
		return nil
	})

	return err
}

func settleValidatorRewards(ctx *context, val *state.Validator, currRound uint64) {
	valAddr := val.MainAddress()
	//special case: collect final residue for offline validator
	if val.Stake.Sign() == 0 && val.RewardsDistributable.Sign() > 0 {
		//local detail
		ctx.recorder.AddReward(valAddr, val.Coinbase, val.RewardsDistributable)

		// actual updates
		ctx.db.AddBalance(val.Coinbase, val.RewardsDistributable)
		newVal := val.PartialCopy()
		newVal.RewardsDistributable.SetUint64(0)
		newVal.RewardsLastSettled = currRound
		ctx.db.UpdateValidator(newVal, val)
		return
	}
	// check if there is rewards
	if val.Stake.Sign() == 0 || val.RewardsDistributable.Sign() == 0 {
		return
	}

	total := new(big.Int).Set(val.RewardsDistributable)
	//validator's commisson
	commisson := new(big.Int)
	if val.CommissionRate > 0 {
		commisson.Mul(total, big.NewInt(int64(val.CommissionRate)))
		commisson.Div(commisson, big.NewInt(int64(params.CommissionRateBase)))
		total.Sub(total, commisson)
	}
	record := &tempRewardsRecord{total: total}
	record.per, record.residue = new(big.Int).QuoRem(record.total, val.Stake, new(big.Int))
	selfReward := new(big.Int).Mul(record.per, val.SelfStake)
	record.total.Sub(record.total, selfReward)
	selfReward.Add(selfReward, commisson)
	ctx.db.AddBalance(val.Coinbase, selfReward)

	//local detail
	ctx.recorder.AddReward(valAddr, val.Coinbase, selfReward)

	// for reuse
	reward := new(big.Int)
	for _, dlg := range val.Delegations {
		reward.SetUint64(0)
		reward.Mul(record.per, dlg.Stake)
		record.total.Sub(record.total, reward)
		if record.total.Sign() < 0 {
			//SHOULD NOT HAPPEN, log for debug
			logging.Crit("validator rewards distribution fatal", "validator", valAddr.String(), "totalRewards", val.RewardsDistributable, "commissionRate", val.CommissionRate, "commission", commisson, "totalStake", val.Stake, "selfStake", val.SelfStake, "perStakeReward", record.per, "expectedResidue", record.residue, "gotResidue", record.total)
		}
		ctx.db.AddBalance(dlg.Delegator, reward)

		//local detail
		ctx.recorder.AddReward(valAddr, dlg.Delegator, reward)
	}
	if record.total.Cmp(record.residue) != 0 {
		//SHOULD NOT HAPPEN, log for debug
		logging.Crit("validator rewards distribution fatal", "validator", valAddr.String(), "totalRewards", val.RewardsDistributable, "commissionRate", val.CommissionRate, "commission", commisson, "totalStake", val.Stake, "selfStake", val.SelfStake, "perStakeReward", record.per, "expectedResidue", record.residue, "gotResidue", record.total)
	}

	// collect residue
	if val.IsOffline() {
		//local detail
		ctx.recorder.AddReward(valAddr, val.Coinbase, record.residue)

		// for a offline validator, takes residue by itself.
		ctx.db.AddBalance(val.Coinbase, record.residue)
		record.residue.SetUint64(0)
	}

	newVal := val.PartialCopy()
	newVal.RewardsDistributable.Set(record.residue)
	newVal.RewardsLastSettled = currRound
	ctx.db.UpdateValidator(newVal, val)
}

// processWithdrawQueue .
// log data format:
// [0,19]   [20,31]
// receipt  arrivalAmount
func processWithdrawQueue(ctx *context) {
	getLogData := func(receipt common.Address, arrivalAmount *big.Int) []byte {
		data := common.BigToHash(arrivalAmount).Bytes()
		copy(data[:common.AddressLength], receipt.Bytes())
		return data
	}

	queue := ctx.db.GetWithdrawQueue()
	var discardRecords []int
	returnAmount := new(big.Int) // for reuse
	for i, record := range queue.Records {
		var (
			release bool
			matured bool
		)
		if record.FinalBalance.Cmp(bigZero) <= 0 { // no more token for withdrawing
			record.Finished = 1
			ctx.receipt.Logs = append(ctx.receipt.Logs, &types.Log{
				Address:     params.StakingModuleAddress,
				Topics:      []common.Hash{common.StringToHash(LogTopicWithdrawResult), record.Operator.Hash()},
				Data:        getLogData(record.Recipient, bigZero),
				BlockNumber: ctx.header.Number.Uint64(),
				TxHash:      record.TxHash,
			})
		} else {
			matured = record.IsMature(ctx.header.Number.Uint64())
			release = matured && (record.Finished == 0)
			if release {
				returnAmount.Set(record.FinalBalance)
				record.Finished = 1
				ctx.db.AddBalance(record.Recipient, returnAmount)

				ctx.receipt.Logs = append(ctx.receipt.Logs, &types.Log{
					Address:     params.StakingModuleAddress,
					Topics:      []common.Hash{common.StringToHash(LogTopicWithdrawResult), record.Operator.Hash()},
					Data:        getLogData(record.Recipient, returnAmount),
					BlockNumber: ctx.header.Number.Uint64(),
					TxHash:      record.TxHash,
				})
			}
		}

		//discard record
		if record.Finished == 1 && (ctx.header.Number.Uint64()-record.CompletionHeight > ctx.config.WithdrawRecordRetention) {
			discardRecords = append(discardRecords, i)
		}
		if release {
			log.Debug("withdraw release", "idx", i, "complete", record.CompletionHeight,
				"matured", matured, "release", release, "final", record.FinalBalance,
				"addr", record.Operator.String(), "returnAmount", returnAmount)
		}
	}

	if len(discardRecords) > 0 {
		ctx.db.RemoveWithdrawRecords(discardRecords)
	}
}

// blockRewards returns the totalRewards for the current block, totalRewards = gasRewards + residue + subsidies
func blockRewards(config *params.YouParams, db *state.StateDB, header *types.Header, residue *big.Int) *big.Int {
	log.Trace("prepare", "number", header.Number, "threshold", config.SubsidyThreshold)

	// totalRewards = gasReward + residue + subsidies
	poolBalance := db.GetBalance(config.RewardsPoolAddress)
	totalRewards := new(big.Int)
	subsidies := new(big.Int)
	gasRewards := new(big.Int).Set(header.GasRewards)
	defaultReward := new(big.Int).Add(gasRewards, residue)

	if defaultReward.IsUint64() && defaultReward.Uint64() < config.SubsidyThreshold && poolBalance.Sign() > 0 {
		subsidiesU64 := ((config.SubsidyThreshold - defaultReward.Uint64()) / 10) * uint64(config.SubsidyCoeff)
		subsidies.SetUint64(subsidiesU64)
		log.Debug("update reward level", "pool", poolBalance, "min", config.SubsidyThreshold, "gasUsed", header.GasUsed, "gasRewards", header.GasRewards, "want", subsidies)
		if poolBalance.Cmp(subsidies) < 0 {
			subsidies.Set(poolBalance)
		}
	}

	if gasRewards.Sign() > 0 {
		totalRewards.Add(totalRewards, gasRewards)
	}
	if residue.Sign() > 0 {
		totalRewards.Add(totalRewards, residue)
	}
	if subsidies.Sign() > 0 {
		db.SubBalance(config.RewardsPoolAddress, subsidies) //from pool
		totalRewards.Add(totalRewards, subsidies)
	}

	// Update header field
	header.Subsidy = new(big.Int).Set(subsidies)

	log.Debug("prepare rewards", "pool", config.RewardsPoolAddress.String(), "balance", poolBalance, "gas", gasRewards, "subsidies", subsidies, "residue", residue, "total", totalRewards)
	return totalRewards
}
