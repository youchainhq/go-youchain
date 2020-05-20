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

package you

import "github.com/youchainhq/go-youchain/metrics"

var (
	nilInPacketsMeter = metrics.NewNilMeter()
	nilInTrafficMeter = metrics.NewNilMeter()

	propTxnInPacketsMeter       = metrics.NewMeter("you_tx_in_packets")
	propTxnInTrafficMeter       = metrics.NewMeter("you_tx_in_traffic")
	propBlockInPacketsMeter     = metrics.NewMeter("you_block_in_packets")
	propBlockInTrafficMeter     = metrics.NewMeter("you_block_in_traffic")
	propBlockHashInPacketsMeter = metrics.NewMeter("you_hash_in_packets")
	propBlockHashInTrafficMeter = metrics.NewMeter("you_hash_in_traffic")
	propHeaderInPacketsMeter    = metrics.NewMeter("you_header_in_packets")
	propHeaderInTrafficMeter    = metrics.NewMeter("you_header_in_traffic")
)
