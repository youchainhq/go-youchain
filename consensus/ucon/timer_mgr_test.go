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

package ucon

import (
	"math/big"
	"testing"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
)

var tm *TimerManager

func TestNewTimerManager(t *testing.T) {
	loops := 100
	if testing.Short() {
		loops = 10
	}

	yp, _ := (&chainReader{}).VersionForRound(0)
	tm = NewTimerManager(processTimeout, processStepEvent)
	tm.startTimer(big.NewInt(1), 2, true, yp.ConsensusTimeout, yp.ConsensusStepInterval)
	logging.Info("start", "time", time.Now())
	tm.Start()

	tm.NewAddressMsg(ReceivedMsgEvent{Round: big.NewInt(1), RoundIndex: uint32(1), Addr: common.Address{0x01}}, params.KindChamber, 10, 10)
	tm.NewAddressMsg(ReceivedMsgEvent{Round: big.NewInt(1), RoundIndex: uint32(2), Addr: common.Address{0x02}}, params.KindChamber, 10, 10)
	tm.NewAddressMsg(ReceivedMsgEvent{Round: big.NewInt(1), RoundIndex: uint32(20), Addr: common.Address{0x03}}, params.KindChamber, 10, 10)
	tm.NewAddressMsg(ReceivedMsgEvent{Round: big.NewInt(1), RoundIndex: uint32(20), Addr: common.Address{0x04}}, params.KindHouse, 10, 10)

	ticker := time.NewTicker(yp.ConsensusTimeout)
	defer ticker.Stop()
	count := 1
	for {
		select {
		case <-ticker.C:
			count += 1
			if count > loops {
				return
			}
		}
	}
}

func processTimeout(round *big.Int, roundIndex uint32) {
	logging.Info("timeout", "time", time.Now())
	tm.Stop()
}

func processStepEvent(step uint32) {
	logging.Info("processStepEvent", "step", step, "time", time.Now())
}

func TestAddressMsgs_NewAddressMsg(t *testing.T) {
	round := big.NewInt(1)
	roundIndex := uint32(1)

	am := NewAddressMsgs()
	am.reset(round, roundIndex, int64(3), true)

	ev := ReceivedMsgEvent{round, roundIndex, common.Address{0x01}, time.Now(), uint64(time.Now().Unix())}
	for i := int64(1); i < 11; i++ {
		ev.Addr = common.BigToAddress(big.NewInt(i))
		am.NewAddressMsg(ev, params.KindHouse, uint64(10), uint64(10))
	}

	for i := int64(11); i < 31; i++ {
		ev.Addr = common.BigToAddress(big.NewInt(i))
		am.NewAddressMsg(ev, params.KindChamber, uint64(10), uint64(10))
	}

	time.Sleep(3 * time.Second)

	ev.Addr = common.BigToAddress(big.NewInt(300))
	oldOver, futureOver, isValid := am.NewAddressMsg(ev, params.KindChamber, uint64(10), uint64(10))
	logging.Info("NewAddressMsg", "oldOver", oldOver, "futureOver", futureOver, "isValid", isValid)

	tmp := make(map[int]common.Address)
	for i := int(101); i < 111; i++ {
		tmp[i] = common.BigToAddress(big.NewInt(int64(i)))
	}
	logging.Info("addr", "len", len(tmp))
	tmpFn := func(a map[int]common.Address, key int) {
		delete(a, key)
	}
	tmpFn(tmp, int(101))
	logging.Info("after", "len", len(tmp))
}
