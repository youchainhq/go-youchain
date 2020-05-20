// Copyright 2020 YOUCHAIN FOUNDATION LTD.
// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import "github.com/youchainhq/go-youchain/metrics"

var (
	// transaction metrics
	metricsTxExecute    = metrics.NewMeter("you_transaction_execute")
	metricsTxExeSuccess = metrics.NewMeter("you_transaction_execute_success")
	metricsTxExeFailed  = metrics.NewMeter("you_transaction_execute_failed")

	// txpool metrics
	metricsPendingTx = metrics.NewGauge("you_txpool_pending")
	metricsQueuedTx  = metrics.NewGauge("you_txpool_queued")
	metricsStalesTx  = metrics.NewGauge("you_txpool_stales")

	metricsAddTx = metrics.NewGauge("you_tx_add") //添加交易

	//block metrics
	metricsBlockHeightGauge  = metrics.NewGauge("you_block_height")
	metricsBlockElapsedGauge = metrics.NewGauge("you_block_elapsed") //记录出块耗时，由于insertChain重复执行，会导致不准确
	metricsBlockProcessTimer = metrics.NewTimer("you_block_process")
	metricsHeadHeaderGauge   = metrics.NewGauge("you_head_header") //当前头链高度
)
