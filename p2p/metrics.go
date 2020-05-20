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

package p2p

import (
	"bytes"
	"fmt"
	"github.com/youchainhq/go-youchain/logging"
	youMetrics "github.com/youchainhq/go-youchain/metrics"
	"github.com/youchainhq/go-youchain/p2p/enode"
	"net"
	"sync"
	"time"

	"github.com/rcrowley/go-metrics"
)

const (
	MetricsInboundTraffic          = "p2p_InboundTraffic"
	MetricsOutboundTraffic         = "p2p_OutboundTraffic"
	MetricsSendMsgQPS              = "p2p_SendMsgQPS"
	MetricsSendMsgQPSFailure       = "p2p_SendMsgQPSFailure"
	HistogramsAPIUsingTimes        = "p2p_APIUsingTimes"
	HistogramsAPIUsingFailureTimes = "p2p_APIUsingTimesFailure"
	HistogramsHandleUsingTimes     = "p2p_HandleUsingTimes"

	HistogramsPMHandleMsgUsingTimes   = "pm_HandleMsgUsingTimes"
	HistogramsBCInsertBlcokUsingTimes = "bc_InsertBlocksUsingTimes"
)

var (
	ingressTrafficMeter            = youMetrics.NewMeter(MetricsInboundTraffic)
	egressTrafficMeter             = youMetrics.NewMeter(MetricsOutboundTraffic)
	sendmsgQPSMetter               = youMetrics.NewMeter(MetricsSendMsgQPS)
	sendmsgQPSFailureMetter        = youMetrics.NewMeter(MetricsSendMsgQPSFailure)
	apiusingTimeHistogr            = youMetrics.NewHistogramWithUniformSample(HistogramsAPIUsingTimes, 4096)
	apiusingTimeFailureHistogr     = youMetrics.NewHistogramWithUniformSample(HistogramsAPIUsingFailureTimes, 4096)
	handleusingTimeHistogr         = youMetrics.NewHistogramWithUniformSample(HistogramsHandleUsingTimes, 4096)
	pmHandleMsgUsingTimesHistogr   = youMetrics.NewHistogramWithUniformSample(HistogramsPMHandleMsgUsingTimes, 4096)
	bcInsertBlockUsingTimesHistogr = youMetrics.NewHistogramWithUniformSample(HistogramsBCInsertBlcokUsingTimes, 4096)

	msgcodeMeter map[uint64]msgcodeinfo
)

type msgcodeinfo struct {
	name       string
	statistics metrics.Meter
}

type meteredConn struct {
	net.PacketConn

	connected time.Time
	ip        net.IP
	id        enode.ID

	trafficMetered bool
	ingressMeter   metrics.Meter // Meter for the read bytes of the peer
	egressMeter    metrics.Meter // Meter for the written bytes of the peer

	lock sync.RWMutex // Lock protecting the metered connection's internals
}

func newMeteredConn(conn net.PacketConn, ingress bool, ip net.IP) net.PacketConn {
	msgcodeMeter = make(map[uint64]msgcodeinfo)
	return &meteredConn{
		PacketConn: conn,
		connected:  time.Now(),
	}
}

func (c *meteredConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(b)
	ingressTrafficMeter.Mark(int64(n))
	c.lock.RLock()
	if c.trafficMetered {
		c.ingressMeter.Mark(int64(n))
	}
	c.lock.RUnlock()
	return n, addr, err
}

func (c *meteredConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = c.PacketConn.WriteTo(p, addr)
	egressTrafficMeter.Mark(int64(n))
	c.lock.RLock()
	if c.trafficMetered {
		c.egressMeter.Mark(int64(n))
	}
	c.lock.RUnlock()
	return n, err
}

func PrintInfo2(freq time.Duration) {
	for _ = range time.Tick(freq) {
		buf := bytes.NewBuffer([]byte(""))
		metrics.WriteOnce(metrics.DefaultRegistry, buf)
		logging.Info("p2p-statistics", "buf", buf.String())
	}
}

func PrintInfo(r metrics.Registry, freq time.Duration) {
	for _ = range time.Tick(freq) {
		var schace string = "p2p--"
		r.Each(func(name string, i interface{}) {
			switch metric := i.(type) {
			case metrics.Counter:
			case metrics.Gauge:
			case metrics.Healthcheck:
				metric.Check()
			case metrics.Histogram:
				h := metric.Snapshot()
				schace += fmt.Sprintf("p2p-- %s\n", name)
				schace += fmt.Sprintf("--  count:       %9d\n", h.Count())
				schace += fmt.Sprintf("--  min:         %s\n", int64ToString(h.Min()))
				schace += fmt.Sprintf("--  max:         %s\n", int64ToString(h.Max()))
				schace += fmt.Sprintf("--  mean:        %s\n", int64ToString(int64(h.Mean())))
			case metrics.Meter:
				m := metric.Snapshot()
				schace += fmt.Sprintf("p2p-- %s\n", name)
				schace += fmt.Sprintf("--  count:       %9d\n", m.Count())
				schace += fmt.Sprintf("--  1-min rate:  %12.2f\n", m.Rate1())
				schace += fmt.Sprintf("--  5-min rate:  %12.2f\n", m.Rate5())
				schace += fmt.Sprintf("--  15-min rate: %12.2f\n", m.Rate15())
				schace += fmt.Sprintf("--  mean rate:   %12.2f\n", m.RateMean())
			case metrics.Timer:
			}
		})
		logging.Info("p2p-statistics", "schace", schace)
	}
}

func privateSendMsgQPS() {
	go sendmsgQPSMetter.Mark(int64(1))
}

func privateSendMsgQPSFailure() {
	sendmsgQPSFailureMetter.Mark(int64(1))
}

func privateAPIUsingTime(start time.Time, failure bool) {
	usingtimes := time.Now().Sub(start)
	if failure {
		apiusingTimeFailureHistogr.Update(int64(usingtimes))
	} else {
		apiusingTimeHistogr.Update(int64(usingtimes))
	}
}

func privateHandleUsingTime(start time.Time) {
	usingtimes := time.Now().Sub(start)
	handleusingTimeHistogr.Update(int64(usingtimes))
}

func int64ToString(d int64) string {

	usingtime := time.Duration(d)

	return usingtime.String()
}

func getNameFromCode(code uint64) (name string) {
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
		name = "msg_ReqSyncBlocksMsg"
	case 0x06:
		name = "msg_RspSyncBlocksMsg"
	case 0x07:
		name = "msg_ConsensusCtrMsg"
	case 0x08:
		name = "msg_ConsensusMsg"
	case 0x09:
		name = "msg_PosTableMsg"
	case 0x0A:
		name = "msg_GetBlockHashByNumberMsg"
	case 0x0B:
		name = "msg_BlockHashByNumberMsg"
	case 0x0C:
		name = "msg_GetBlockHeadersMsg"
	case 0x0D:
		name = "msg_BlockHeadersMsg"
	case 0x0E:
		name = "msg_GetNodeDataMsg"
	case 0x0F:
		name = "msg_NodeDataMsg"
	default:
		name = ""
	}

	return name
}

var (
	msginfomu sync.Mutex
)

func privateMsgInfo(code uint64, size int64) {
	msginfomu.Lock()
	defer msginfomu.Unlock()
	if _, ok := msgcodeMeter[code]; !ok {
		name := getNameFromCode(code)
		if len(name) == 0 {
			return
		}

		h := youMetrics.NewMeter(name)
		msgcodeMeter[code] = msgcodeinfo{
			name:       name,
			statistics: h,
		}
	}

	msgcodeMeter[code].statistics.Mark(size)

}

func PublicPMHandleMsgUsingTime(start time.Time) {
	usingtimes := time.Now().Sub(start)
	pmHandleMsgUsingTimesHistogr.Update(int64(usingtimes))
}

func PublicBCInsertBlockUsingTime(start time.Time) {
	usingtimes := time.Now().Sub(start)
	bcInsertBlockUsingTimesHistogr.Update(int64(usingtimes))
}

func (c *meteredConn) Close() error {
	err := c.PacketConn.Close()
	return err
}
