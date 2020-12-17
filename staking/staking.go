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
	"sync"

	"github.com/youchainhq/go-youchain/bls"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/params"
)

//Staking staking container
type Staking struct {
	blockChain   *core.BlockChain
	engine       engine
	eventMux     *event.TypeMux
	evidences    []Evidence
	votesWatcher *votesWatcher
	blsMgr       bls.BlsManager
	mutex        sync.RWMutex // global mutex for locking chain operations
	quit         chan struct{}
}

//NewStaking create a staking obj
func NewStaking(mux *event.TypeMux) *Staking {
	return &Staking{
		blsMgr:    bls.NewBlsManager(),
		eventMux:  mux,
		evidences: []Evidence{},
		quit:      make(chan struct{}),
	}
}

//Register reg module to router
func (s *Staking) Register(router core.IRouter) {
	router.AddTxConverter(params.StakingModuleAddress, &TxConverter{})
	router.AddEndBlockHook(Module, EndBlock(s))
}

//Start start staking module, blockchain and cons-engine are required
func (s *Staking) Start(blockChain *core.BlockChain, eng interface{}) error {
	if blockChain == nil {
		return errors.New("blockchain required")
	}
	s.blockChain = blockChain
	if eng == nil {
		return errors.New("engine required")
	}
	e, ok := eng.(engine)
	if !ok {
		return errors.New("engine not matched")
	}
	s.engine = e

	s.votesWatcher = newVotesWatcher(s.blockChain, s.engine)
	if s.eventMux != nil {
		evidenceChan := make(chan EvidenceInactive, 256) // intermediate channel
		go func() {
			for {
				select {
				case e := <-evidenceChan:
					_ = s.eventMux.Post(NewEvidence(e))
				case <-s.quit:
					log.Info("Staking Stop #1")
					return
				}
			}
		}()
		go func() {
			subs := s.eventMux.Subscribe(Evidence{}, core.InsertBlockEvent{})
			defer func() {
				subs.Unsubscribe()
			}()

			for {
				select {
				case evt := <-subs.Chan():
					if evt == nil {
						return
					}
					switch evt.Data.(type) {
					case Evidence:
						s.mutex.Lock()
						s.evidences = append(s.evidences, evt.Data.(Evidence))
						s.mutex.Unlock()
					case core.InsertBlockEvent:
						ev := evt.Data.(core.InsertBlockEvent)
						if ev.Block != nil {
							addresses := s.votesWatcher.Inactive(ev.Block.NumberU64(), s.inactiveCheckingRange())
							if len(addresses) > 0 {
								evidenceChan <- EvidenceInactive{Round: ev.Block.NumberU64(), Validators: addresses}
							}
						} else {
							log.Error("InsertBlockEvent no block")
						}
					}
				case <-s.quit:
					log.Error("s.quit quit")
					return
				}
			}
		}()
	} else {
		log.Warn("no eventMux")
	}
	return nil
}

//Stop stop staking module
func (s *Staking) Stop() {
	close(s.quit)
}

//inactiveCheckingRange inactiveCheckingRange should be less than stakeLookBack
func (s *Staking) inactiveCheckingRange() uint64 {
	return uint64(params.MinStakeLookBack() - 1)
}
