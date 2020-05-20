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
	"fmt"
	"sync"
	"time"

	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/p2p"
	"github.com/youchainhq/go-youchain/p2p/enode"
)

type Counter struct {
	//events event.Feed
	events chan *p2p.PeerEvent
	init   bool

	lock sync.RWMutex
	wg   sync.WaitGroup

	ctx      context.Context
	doCancel context.CancelFunc

	peerReport struct {
		addm  map[string]uint64
		dropm map[string]uint64
	}

	msgRecvReport struct {
		count map[string]uint64
		msize map[string]uint64
	}

	msgSendReport struct {
		count map[string]uint64
		msize map[string]uint64
	}

	//1. add count
	//2. drop count
	//3. msg count
}

func NewNetwork(ctx context.Context) *Counter {
	selfctx, cancel := context.WithCancel(ctx)
	net := &Counter{
		events:   make(chan *p2p.PeerEvent),
		ctx:      selfctx,
		doCancel: cancel,
		init:     false,
	}

	net.peerReport.addm = make(map[string]uint64)
	net.peerReport.dropm = make(map[string]uint64)
	net.msgRecvReport.count = make(map[string]uint64)
	net.msgRecvReport.msize = make(map[string]uint64)
	net.msgSendReport.count = make(map[string]uint64)
	net.msgSendReport.msize = make(map[string]uint64)

	return net
}

func (net *Counter) Events() chan *p2p.PeerEvent {
	return net.events
}

func (net *Counter) Start() {
	if net.init {
		return
	}
	var errc = make(chan error)
	select {
	case <-net.ctx.Done():
		return
	default:

		net.wg.Add(1)
		go func() {
			net.watchEvents(net.events, errc)
			net.wg.Done()
		}()
		net.init = true
	}

	select {
	case <-net.ctx.Done():
	case <-errc:
		net.doCancel()
	}
}

func (net *Counter) Stop() error {
	net.lock.Lock()
	defer net.lock.Unlock()
	if !net.init {
		return fmt.Errorf("monitor don`t setup")
	}

	net.doCancel()
	net.wg.Wait()
	net.init = false

	return nil
}

func (net *Counter) watchEvents(events chan *p2p.PeerEvent, errc chan error) {
	defer func() {
		logging.Info("p2p monitor", "watchEvents quit", time.Now().String())
	}()

	var (
		peers = make(map[enode.ID]time.Time)
	)

	for {
		select {
		case <-net.ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}

			peerID := event.Peer
			switch event.Type {
			case p2p.PeerEventTypeAdd:
				if t, ok := peers[peerID]; ok {
					logging.Error("monitor", "Add peer failed", event.IP, "Enode", event.Enode, "reason", "already exist", "error", event.Error, "add time", t.String())
				} else {
					peers[peerID] = time.Now()
					logging.Info("monitor", "Add peer success", event.IP, "Enode", event.Enode, "add time", time.Now().String())
					net.peerReport.addm[event.IP] += uint64(1)
					logging.Info("Peer add report", "add count", net.peerReport.addm[event.IP], "drop count", net.peerReport.dropm[event.IP])
				}
			case p2p.PeerEventTypeDrop:
				if t, ok := peers[peerID]; ok {
					delete(peers, peerID)
					logging.Info("monitor", "Drop peer success", event.IP, "Enode", event.Enode, "error", event.Error, "time of duration", time.Now().Sub(t).String())
					net.peerReport.dropm[event.IP] += uint64(1)
					logging.Trace("Peer add report", "add count", net.peerReport.addm[event.IP], "drop count", net.peerReport.dropm[event.IP])
				} else {
					logging.Error("monitor", "Drop peer failed", peerID, "reason", "don`t exist")
				}
			case p2p.PeerEventTypeMsgRecv:
				code := msgCodeByName(*event.MsgCode)
				net.msgRecvReport.count[code] += uint64(1)
				net.msgRecvReport.msize[code] += uint64(*event.MsgSize)
				logging.Debug("monitor", "Recv msg", msgCodeByName(*event.MsgCode), "msg size", *event.MsgSize, "total count", net.msgRecvReport.count[code], "total size", net.msgRecvReport.msize[code], "IP", event.IP, "Enode", event.Enode, "protocol", event.Protocol)
			case p2p.PeerEventTypeMsgSend:
				code := msgCodeByName(*event.MsgCode)
				net.msgSendReport.count[code] += uint64(1)
				net.msgSendReport.msize[code] += uint64(*event.MsgSize)
				logging.Debug("monitor", "Send msg", msgCodeByName(*event.MsgCode), "msg size", *event.MsgSize, "total count", net.msgSendReport.count[code], "total size", net.msgSendReport.msize[code], "IP", event.IP, "Enode", event.Enode, "protocol", event.Protocol)
			case p2p.PeerEventTypeReadChanCount:
				logging.Info("monitor", "Channel count", event.Count, "IP", event.IP, "Enode", event.Enode)
			}
		}
	}
}

func msgCodeByName(code uint64) (name string) {
	switch code {
	case 0x00:
		name = "msg_StatusMsg"
	case 0x01:
		name = "msg_NewBlockMsg"
	case 0x02:
		name = "msg_NewBlockHashMsg"
	case 0x03:
		name = "msg_TxMsg"
	case 0x04:
		name = "msg_GetBlockMsg"
	case 0x05:
		name = "msg_ConsensusCtrMsg"
	case 0x06:
		name = "msg_ConsensusMsg"
	case 0x07:
		name = "msg_GetBlockHeadersMsg"
	case 0x08:
		name = "msg_BlockHeadersMsg"
	case 0x09:
		name = "msg_GetNodeDataMsg"
	case 0x0A:
		name = "msg_NodeDataMsg"
	case 0x0B:
		name = "msg_GetBlockBodiesMsg"
	case 0x0C:
		name = "msg_BlockBodiesMsg"
	case 0x0D:
		name = "msg_GetReceiptsMsg"
	case 0x0E:
		name = "msg_ReceiptsMsg"
	default:
		name = ""
	}

	return name
}
