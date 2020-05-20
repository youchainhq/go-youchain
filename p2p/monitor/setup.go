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

package monitor

import (
	"context"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/p2p"
)

var (
	_setup *setup
)

type setup struct {
	net      *Counter
	ctx      context.Context
	doCancel context.CancelFunc
	ok       bool
	sub      event.Subscription
}

func Start() chan *p2p.PeerEvent {
	if _setup == nil {
		ctx, cancel := context.WithCancel(context.TODO())
		net := NewNetwork(ctx)
		_setup = &setup{
			net:      net,
			ctx:      ctx,
			doCancel: cancel,
			ok:       false,
		}

	}
	if !_setup.ok {
		go _setup.net.Start()
	}

	return _setup.net.Events()
}

func SetSubscription(sub event.Subscription) {
	if _setup != nil {
		_setup.sub = sub
	}
}

func Unsubscription() {
	if _setup != nil {
		_setup.sub.Unsubscribe()
	}
}

func Stop() {
	if _setup != nil && _setup.ok {
		_setup.doCancel()
		_ = _setup.net.Stop()
		_setup.ok = false
		_setup = nil
	}
}
