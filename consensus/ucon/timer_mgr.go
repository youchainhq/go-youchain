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
	"sync"
	"time"

	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/params"
)

const OutdateFaultTolerance int64 = 10
const MaxMsgsSingleInterval int64 = 10 // s

type ProcessTimeoutFn func(round *big.Int, roundIndex uint32)
type ProcessStepFn func(step uint32)

type AddressMsgInfo struct {
	receivedAt int64
	round      *big.Int
	roundIndex uint32
	sendAt     int64
}

type AddressMap map[common.Address]*AddressMsgInfo //time.Time

func (am AddressMap) addNewItem(addr common.Address, round *big.Int, roundIndex uint32, timestamp int64, sendAt uint64) {
	if am[addr] != nil && am[addr].sendAt < int64(sendAt) {
		am[addr].receivedAt = timestamp
		am[addr].round = round
		am[addr].roundIndex = roundIndex
		am[addr].sendAt = int64(sendAt)
	} else if am[addr] == nil {
		am[addr] = &AddressMsgInfo{
			receivedAt: timestamp,
			round:      round,
			roundIndex: roundIndex,
			sendAt:     int64(sendAt),
		}
	}
}

func (am AddressMap) removeItem(addr common.Address) {
	delete(am, addr)
}

func (am AddressMap) compareTime(addr common.Address, timestamp uint64) bool {
	if am[addr] != nil && am[addr].sendAt-MaxMsgsSingleInterval > int64(timestamp) {
		logging.Error("CompareTime failed.", "addr", addr.String(), "last", am[addr].sendAt, "cur", timestamp)
		return true
	} else {
		return false
	}
}

type AddressMsgs struct {
	lock       sync.Mutex
	round      *big.Int
	roundIndex uint32

	oldAddrMap    map[params.ValidatorKind]AddressMap
	futureAddrMap map[params.ValidatorKind]AddressMap

	maxInterval int64
}

func NewAddressMsgs() *AddressMsgs {
	am := &AddressMsgs{}
	am.oldAddrMap = make(map[params.ValidatorKind]AddressMap)
	am.oldAddrMap[params.KindChamber] = make(map[common.Address]*AddressMsgInfo) //make(map[RoundIndexHash]AddressList)
	am.oldAddrMap[params.KindHouse] = make(map[common.Address]*AddressMsgInfo)   //make(map[RoundIndexHash]AddressList)

	am.futureAddrMap = make(map[params.ValidatorKind]AddressMap)
	am.futureAddrMap[params.KindChamber] = make(map[common.Address]*AddressMsgInfo)
	am.futureAddrMap[params.KindHouse] = make(map[common.Address]*AddressMsgInfo)

	return am
}

func (am *AddressMsgs) reset(round *big.Int, roundIndex uint32, maxInterval int64, clear bool) {
	am.lock.Lock()
	defer am.lock.Unlock()

	if round == nil {
		return
	}
	am.round = round
	am.roundIndex = roundIndex
	am.maxInterval = maxInterval + OutdateFaultTolerance // maybe exist a difference between machines' local time
}

func (am *AddressMsgs) NewAddressMsg(ev ReceivedMsgEvent, validatorKind params.ValidatorKind, chamberNum, houseNum uint64) (oldOver, futureOver, isValid bool) {
	am.lock.Lock()
	defer am.lock.Unlock()

	if ev.Round == nil || am.round == nil { //} || ev.Round.Cmp(am.round) != 0 {
		logging.Error("NewAddressMsg failed 1.", "ev", ev, "am", am)
		return
	}

	if am.oldAddrMap[validatorKind].compareTime(ev.Addr, ev.SendAt) || am.futureAddrMap[validatorKind].compareTime(ev.Addr, ev.SendAt) {
		logging.Error("NewAddressMsg failed 2.", "ev", ev)
		return
	}

	overFn := func(sNum, mNum int) bool {
		chamberPro := int(float64(chamberNum) * DefaultMsgTimerProportion)
		housePro := int(float64(houseNum) * DefaultMsgTimerProportion)
		if sNum >= chamberPro && mNum >= housePro {
			return true
		}
		return false
	}

	isValid = true
	cr := am.round.Cmp(ev.Round)
	//if cr > 0 && (am.round.Uint64()-ev.Round.Uint64()) > OldRoundMaxInterval {
	//	return
	//}
	if cr > 0 || (cr == 0 && ev.RoundIndex <= am.roundIndex) {
		am.oldAddrMap[validatorKind].addNewItem(ev.Addr, ev.Round, ev.RoundIndex, ev.ReceivedAt.Unix(), ev.SendAt)
		am.futureAddrMap[validatorKind].removeItem(ev.Addr)

		chamberMsgsNum, houseMsgsNum := am.clearOutdatedMsgs(true, ev.Round, ev.RoundIndex)
		oldOver = overFn(chamberMsgsNum, houseMsgsNum)
		if oldOver {
			logging.Debug("OldOver.", "Round", am.round, "RoundIndex", am.roundIndex, "chamberMsgsNum", chamberMsgsNum, "chamberThreshold", chamberNum, "houseMsgsNum", houseMsgsNum, "houseThreshold", houseNum)
		}
		return
	} else {
		am.futureAddrMap[validatorKind].addNewItem(ev.Addr, ev.Round, ev.RoundIndex, ev.ReceivedAt.Unix(), ev.SendAt)
		am.oldAddrMap[validatorKind].removeItem(ev.Addr)

		chamberMsgsNum, houseMsgsNum := am.clearOutdatedMsgs(false, ev.Round, ev.RoundIndex)
		futureOver = overFn(chamberMsgsNum, houseMsgsNum)
		logging.Debug("newAddressMsg", "Round", am.round, "RoundIndex", am.roundIndex, "FutureOver", futureOver, "chamberMsgsNum", chamberMsgsNum, "chamberThreshold", chamberNum, "houseMsgsNum", houseMsgsNum, "houseThreshold", houseNum)
		return
	}
}

func (am *AddressMsgs) clearOutdatedMsgs(isOld bool, round *big.Int, roundIndex uint32) (chamberMsgsNum, houseMsgsNum int) {
	var addrMsgs map[params.ValidatorKind]AddressMap
	if isOld {
		addrMsgs = am.oldAddrMap
	} else {
		addrMsgs = am.futureAddrMap
	}

	clearFn := func(addrMap AddressMap) (count int) {
		for addr, item := range addrMap {
			interval := time.Now().Unix() - item.receivedAt
			if interval > am.maxInterval {
				delete(addrMap, addr)
				continue
			}

			if isOld {
				count += 1
			} else if round.Cmp(item.round) == 0 && roundIndex == item.roundIndex {
				count += 1
			}
		}
		return
	}

	chamberMsgsNum = clearFn(addrMsgs[params.KindChamber])

	houseMsgsNum = clearFn(addrMsgs[params.KindHouse])

	return
}

type TimerManager struct {
	lock          sync.Mutex
	round         *big.Int
	roundIndex    uint32
	maxRoundIndex uint32

	timeoutTimer        *time.Timer
	currentTimeout      time.Duration
	stepTimer           *time.Timer //time.Ticker
	currentStepInterval time.Duration

	counter  uint32
	quitChan chan bool

	processTimeoutFn ProcessTimeoutFn
	processStepFn    ProcessStepFn

	addrMsgs *AddressMsgs
}

func NewTimerManager(timeoutFn ProcessTimeoutFn, stepFn ProcessStepFn) *TimerManager {
	tm := TimerManager{
		quitChan:         make(chan bool, 1),
		processTimeoutFn: timeoutFn,
		processStepFn:    stepFn,
		addrMsgs:         NewAddressMsgs(),
	}

	return &tm
}

func (tm *TimerManager) Start() {
	go tm.timerLoop()
}

// should be called when start a new round of consensus
func (tm *TimerManager) startTimer(round *big.Int, roundIndex uint32, newRound bool, timeout time.Duration, stepInterval time.Duration) {
	tm.lock.Lock()
	defer tm.lock.Unlock()

	//deadline := timeout //+ stepInterval * 5 * (int(roundIndex)-1)
	//for i := 1; i < int(roundIndex); i++ {
	//	deadline = deadline + stepInterval * 2
	//}

	if round == nil {
		return
	}
	//if tm.round == nil || round.Cmp(tm.round) != 0 {
	//	tm.round = round
	//	tm.addrMsgs.reset(round, roundIndex)
	//}

	tm.round = round
	tm.roundIndex = roundIndex
	tm.maxRoundIndex = roundIndex
	tm.currentTimeout = timeout
	tm.currentStepInterval = stepInterval

	logging.Info("StartTimer.", "Round", tm.round, "RoundIndex", tm.roundIndex, "MaxRoundIndex", tm.maxRoundIndex)

	deadline := timeout //+ time.Duration(tm.roundIndex)*time.Second
	if tm.timeoutTimer == nil {
		tm.timeoutTimer = time.NewTimer(deadline)
	} else {
		tm.timeoutTimer.Reset(deadline)
	}

	tm.addrMsgs.reset(round, roundIndex, int64(deadline.Seconds()), newRound)

	if tm.stepTimer == nil {
		tm.stepTimer = time.NewTimer(stepInterval) //time.NewTicker(stepInterval)//
	} else {
		tm.stepTimer.Reset(stepInterval)
	}

	tm.counter = UConStepStart
}

// should be called when stop the consensus server
func (tm *TimerManager) Stop() {
	tm.lock.Lock()
	defer tm.lock.Unlock()

	if tm.timeoutTimer != nil {
		tm.timeoutTimer.Stop()
	}
	if tm.stepTimer != nil {
		tm.stepTimer.Stop()
	}

	close(tm.quitChan)
}

func (tm *TimerManager) NewAddressMsg(ev ReceivedMsgEvent, validatorKind params.ValidatorKind, chamberNum, houseNum uint64) bool {
	tm.lock.Lock()
	defer tm.lock.Unlock()

	if ev.Round == nil { //} || ev.Round.Cmp(tm.round) != 0 {
		logging.Error("NewAddressMsg failed", "err", "round is empty")
		return false
	}
	if tm.round == nil {
		return true
	}

	oldOver, futureOver, isValid := tm.addrMsgs.NewAddressMsg(ev, validatorKind, chamberNum, houseNum)
	if !isValid {
		logging.Error("NewAddressMsg failed", "ev", ev)
		return false
	}
	//if tm.maxRoundIndex > ev.RoundIndex {
	//	return
	//}
	if oldOver {
		//interval := tm.timeout + time.Duration(tm.roundIndex)*time.Second
		tm.timeoutTimer.Reset(tm.currentTimeout)
		//log.Info("ResetTimeoutTimer.", "Round", tm.round, "RoundIndex", tm.roundIndex, "MaxRoundIndex", tm.maxRoundIndex, "ChamberNum", chamberNum, "HouseNum", houseNum)
		return true
	}

	if futureOver && tm.maxRoundIndex < ev.RoundIndex && ev.Round.Cmp(tm.round) == 0 {
		tm.maxRoundIndex = ev.RoundIndex
		logging.Info("UpdateMaxRoundIndex.", "Round", tm.round, "RoundIndex", tm.roundIndex, "MaxRoundIndex", tm.maxRoundIndex, "ChamberNum", chamberNum, "HouseNum", houseNum)
	}
	return true
}

// should be called when start the consensus server
func (tm *TimerManager) timerLoop() {
	//stepTicker := time.NewTicker(tm.stepInterval)
	//defer stepTicker.Stop()

	for {
		select {
		case <-tm.quitChan:
			logging.Info("stop stepTimer")
			return

		case <-tm.timeoutTimer.C:
			logging.Info("Timer: time out.", "Round", tm.round, "RoundIndex", tm.roundIndex, "MaxRoundIndex", tm.maxRoundIndex)
			tm.timeoutTimer.Stop()
			tm.processTimeoutFn(tm.round, tm.maxRoundIndex)

		case <-tm.stepTimer.C:
			tm.counter += 1
			tm.processStepFn(tm.counter)
			tm.stepTimer.Reset(tm.currentStepInterval)
			//case <-stepTicker.C:
			//	tm.counter += 1
			//	tm.processStepFn(tm.counter)
		}
	}
}
