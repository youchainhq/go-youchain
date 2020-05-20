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

package check

import (
	"context"
	"crypto/ecdsa"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/p2p/netutil"
	"net"
	"sync"
)

var (
	natService *NATService = nil
	log                    = logging.New("NAT", "Server")
)

type message struct {
	to     *net.UDPAddr
	packet []byte
}

type NATConn struct {
	*net.UDPConn
	priv   *ecdsa.PrivateKey
	recvc  chan *message
	commit chan *message

	wmu  sync.Mutex
	wait sync.WaitGroup
}

type NATService struct {
	master *NATConn
	slave  *NATConn
	cancel context.CancelFunc
	wait   sync.WaitGroup
}

func NewNATService(privateKey *ecdsa.PrivateKey, masterAddr, slaveAddr *net.UDPAddr) *NATService {
	if natService == nil {
		master, err := net.ListenUDP("udp", masterAddr)
		if err != nil {
			log.Error("NewNATService", "setup master listener err", err)
			return nil
		}
		slave, err := net.ListenUDP("udp", slaveAddr)
		if err != nil {
			log.Error("setup slave listener err", err)
			return nil
		}

		natService = &NATService{
			master: newConn(master, privateKey),
			slave:  newConn(slave, privateKey),
		}
	}

	return natService
}

func (nat *NATService) Close() {
	nat.master.Close()
	nat.slave.Close()
	if nat.cancel != nil {
		nat.cancel()
	}
	nat.wait.Wait()
}

func (nat *NATService) Start() {
	nat.wait.Add(1)
	defer nat.wait.Done()
	ctx, cancel := context.WithCancel(context.TODO())
	nat.cancel = cancel
	go nat.master.start(ctx)
	go nat.slave.start(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-nat.master.commit:
			log.Info("Start", "master commit", msg.to.String())
			if msg != nil {
				nat.slave.recvc <- msg
			}
		case msg := <-nat.slave.commit:
			log.Info("Start", "slave commit", msg.to.String())
			if msg != nil {
				nat.master.recvc <- msg
			}
		}
	}
}

func newConn(udp *net.UDPConn, priv *ecdsa.PrivateKey) *NATConn {
	return &NATConn{
		UDPConn: udp,
		priv:    priv,
		recvc:   make(chan *message),
		commit:  make(chan *message),
	}
}

func (conn *NATConn) start(ctx context.Context) {
	conn.wait.Add(2)
	go conn.readloop(ctx)
	go conn.run(ctx)

	conn.wait.Wait()
}

func (conn *NATConn) readloop(ctx context.Context) {
	defer conn.wait.Done()
	buf := make([]byte, 1024)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			nbytes, from, err := conn.ReadFromUDP(buf)
			if netutil.IsTemporaryError(err) {
				log.Warn("Temporary UDP read error", "err", err)
				continue
			} else if err != nil {
				log.Error("UDP read error", "err", err)
				return
			}

			if ptype, err := conn.handlePacket(from, buf[:nbytes]); err != nil {
				log.Error("handlePacket", "process err", err, "Packet", ptype.String())
			}
		}
	}
}

func (conn *NATConn) run(ctx context.Context) {
	defer conn.wait.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-conn.recvc:
			_, err := conn.WriteToUDP(msg.packet, msg.to)
			if err != nil {
				log.Error("run", "WriteToUDP err", err)
			} else {
				log.Info("run", "send to:", msg.to.String(), "form:", conn.LocalAddr().String())
			}
		}
	}
}

func (conn *NATConn) DialTo(to *net.UDPAddr, packet []byte) error {
	log.Info("Dial to ", to.String(), "server", conn.LocalAddr().String())
	conn.wmu.Lock()
	defer conn.wmu.Unlock()
	c, err := net.Dial("udp", to.String())
	if err != nil {
		log.Error("DialTo", "NATConn Dial err", err, "dial to", to.String())
		return err
	}

	defer c.Close()
	_, err = c.Write(packet)
	if err != nil {
		log.Error("DialTo", "conn Write err", err)
	}

	return err
}

func (conn *NATConn) IP() net.IP {
	udpaddr, _ := conn.LocalAddr().(*net.UDPAddr)
	return udpaddr.IP
}

func (conn *NATConn) Port() int {
	udpaddr, _ := conn.LocalAddr().(*net.UDPAddr)
	return udpaddr.Port
}

func (conn *NATConn) handlePacket(from *net.UDPAddr, buf []byte) (packettype, error) {
	packet, fromID, hash, err := decodePacket(buf)
	if err != nil {
		log.Error("Bad request packet", "addr", from, "err", err)
		return unknownPacket, err
	}

	return packet.handle(conn, from, fromID, hash)
}

func (conn *NATConn) send(toaddr *net.UDPAddr, ptype packettype, req packet) ([]byte, error) {
	packet, hash, err := encodePacket(conn.priv, ptype, req)
	if err != nil {
		return hash, err
	}
	_, err = conn.WriteToUDP(packet, toaddr)
	return hash, err
}
