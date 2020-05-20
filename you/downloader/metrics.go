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

package downloader

import "github.com/youchainhq/go-youchain/metrics"

var (
	headerInMeter      = metrics.NewMeter("you-downloader-headers-in")
	headerReqTimer     = metrics.NewTimer("you-downloader-headers-req")
	headerDropMeter    = metrics.NewMeter("you-downloader-headers-drop")
	headerTimeoutMeter = metrics.NewMeter("you-downloader-headers-timeout")

	bodyInMeter      = metrics.NewMeter("you-downloader-bodies-in")
	bodyReqTimer     = metrics.NewTimer("you-downloader-bodies-req")
	bodyDropMeter    = metrics.NewMeter("you-downloader-bodies-drop")
	bodyTimeoutMeter = metrics.NewMeter("you-downloader-bodies-timeout")

	receiptInMeter      = metrics.NewMeter("you-downloader-receipts-in")
	receiptReqTimer     = metrics.NewTimer("you-downloader-receipts-req")
	receiptDropMeter    = metrics.NewMeter("you-downloader-receipts-drop")
	receiptTimeoutMeter = metrics.NewMeter("you-downloader-receipts-timeout")

	stateInMeter   = metrics.NewMeter("you-downloader-nodes-in")
	stateDropMeter = metrics.NewMeter("you-downloader-nodes-drop")
)
