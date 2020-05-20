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
	"crypto/ecdsa"
	"fmt"
	"github.com/ccding/go-stun/stun"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/p2p/enode"
	"net"
	"sync"
	"time"
)

var (
	readTimeout  = 5 * time.Second
	writeTimeout = 10 * time.Second

	NatPublicService string
	NatMasterAddr    string
	NatSlaveAddr     string
)

type StatusStep uint8

var (
	// Step 1, Check whether the client is capable of UDP communication and is behind a NAT
	Step1 StatusStep = 0x01
	// Step 2, Check whether the client NAT is Full Cone NAT
	Step2 StatusStep = 0x02
	// Step 3, Check whether the client NAT is symmetric NAT
	Step3 StatusStep = 0x03
	// Step 4, Check whether the client NAT is Restricted Cone NAT
	Step4 StatusStep = 0x04
	// Step 5, Check whether the client NAT Port Restricted Cone NAT
	Step5 StatusStep = 0x05
	// Step 6, finished
	Step6 StatusStep = 0x06
)

type NATClient struct {
	master, slave *net.UDPAddr
	privateKey    *ecdsa.PrivateKey
	currentStep   StatusStep
	lock          sync.Mutex
	externalRPC   rpcEndpoint
	ips           []net.IP
	conn          *net.UDPConn

	listenPort int
}

func NewNATClient(priv *ecdsa.PrivateKey, master, slave *net.UDPAddr) *NATClient {

	localips := getLocalIPs()
	localip := []net.IP{}

	for _, v := range localips {
		if !v.IP.IsLoopback() {
			localip = append(localip, v.IP)
		}
	}

	return &NATClient{
		master:      master,
		slave:       slave,
		currentStep: Step1,
		privateKey:  priv,
		ips:         localip,
	}
}

func NewNATClientAssignPort(priv *ecdsa.PrivateKey, master, slave *net.UDPAddr, listenPort int) *NATClient {

	localips := getLocalIPs()
	localip := []net.IP{}

	for _, v := range localips {
		if !v.IP.IsLoopback() {
			localip = append(localip, v.IP)
		}
	}

	return &NATClient{
		master:      master,
		slave:       slave,
		currentStep: Step1,
		privateKey:  priv,
		ips:         localip,
		listenPort:  listenPort,
	}
}

func (c *NATClient) Discover() *enode.NATType {
	//setp1
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.conn == nil {
		var (
			conn *net.UDPConn
			err  error
		)
		if c.listenPort <= 0 {
			conn, err = net.ListenUDP("udp", nil)
			if err != nil {
				natType := enode.NATUnknown
				return &natType
			}
		} else {
			udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", c.listenPort))
			if err != nil {
				natType := enode.NATUnknown
				log.Error("resolve udp addr failed", "err", err)
				return &natType
			}

			log.Info("udp addr", "udpaddr", udpAddr)

			conn, err = net.ListenUDP("udp", udpAddr)
			if err != nil {
				natType := enode.NATUnknown
				log.Error("listen UDP udp addr failed", "err", err)
				return &natType
			}
		}
		c.conn = conn
	}
	defer c.conn.Close()

	natType, s, err := c.step1(c.conn, false)
	if s == Step6 {
		return natType
	}
	if err != nil {
		return natType
	}

	natType, s, err = c.step23(c.conn, false)
	if s == Step6 {
		return natType
	}

	if err != nil && natType != nil {
		return natType
	}

	natType, s, err = c.step4(c.conn)
	return natType
}

func readPacket(conn *net.UDPConn) (packet, error) {
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	nbytes, from, err := conn.ReadFromUDP(buf)
	if err != nil {
		log.Error("UDP read error", "err", err)
		return nil, err
	}

	pag, err := handlePacket(conn, from, buf[:nbytes])
	if err != nil {
		log.Error("read", "process Packet err", err)
		return nil, err
	}

	return pag, nil
}

func handlePacket(conn *net.UDPConn, from *net.UDPAddr, buf []byte) (packet, error) {
	packet, fromID, _, err := decodePacket(buf)
	if err != nil {
		log.Error("Bad request packet", "addr", from, "err", err)
		return nil, err
	}

	_, err = decodePubkey(fromID)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %s", err)
	}

	return packet, nil
}

func (c *NATClient) step1(conn net.Conn, connFlag bool) (*enode.NATType, StatusStep, error) {
	selfAddr := c.conn.LocalAddr().(*net.UDPAddr)
	req := reqExternalIP{
		Version: Version,
		From:    rpcEndpoint{IP: selfAddr.IP, UDP: uint(selfAddr.Port)},
		To:      rpcEndpoint{IP: c.master.IP, UDP: uint(c.master.Port)},
	}

	ntype := enode.NATUnknown
	_, err := c.send(conn, connFlag, c.master, reqExternalIPPacket, &req)
	if err != nil {
		return &ntype, Step1, err
	}

	pag, err := readPacket(conn.(*net.UDPConn))
	if err != nil {
		log.Error("step1", "read err:", err)
		return &ntype, Step6, err
	}
	if resp, ok := pag.(*respExternalIP); ok {
		c.externalRPC = resp.External
		log.Debug("step1", "ip:", resp.External.IP.String(), "UDP:", resp.External.UDP, "self IP:", selfAddr.IP, "port:", selfAddr.Port)

		for _, v := range c.ips {
			if resp.External.IP.Equal(v) && resp.External.UDP == uint(selfAddr.Port) {
				c.currentStep = Step2
				return nil, Step2, nil
			} else {
				c.currentStep = Step3
				return nil, Step3, nil
			}
		}
	}

	return &ntype, Step1, fmt.Errorf("invalid respose packet")
}

func (c *NATClient) send(conn net.Conn, connFlag bool, toaddr *net.UDPAddr, ptype packettype, req packet) ([]byte, error) {
	packet, hash, err := encodePacket(c.privateKey, ptype, req)
	if err != nil {
		return hash, err
	}

	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if connFlag {
		_, err := conn.Write(packet)
		return nil, err
	} else {
		_, err := conn.(*net.UDPConn).WriteToUDP(packet, toaddr)
		return nil, err
	}
}

func (c *NATClient) step23(conn net.Conn, connFlag bool) (*enode.NATType, StatusStep, error) {
	udpaddr := c.conn.LocalAddr().(*net.UDPAddr)
	req := reqOtherIPAndPort{
		Version: Version,
		From:    rpcEndpoint{IP: udpaddr.IP, UDP: uint(udpaddr.Port)},
		To:      rpcEndpoint{IP: c.slave.IP, UDP: uint(c.slave.Port)},
	}

	ntype := enode.NATUnknown

	_, err := c.send(conn, false, c.master, reqOtherIPAndPortPacket, &req)
	if err != nil {
		log.Error("step2->3", "err", err)
		return &ntype, c.currentStep, err
	}

	pag, err := readPacket(conn.(*net.UDPConn))
	if err != nil {
		log.Error("step2->3 read", "read err:", err)
		if c.currentStep == Step2 {
			ntype = enode.NATSymmetricUDPFirewall
			c.currentStep = Step6
			return &ntype, Step6, err
		} else if c.currentStep == Step3 {
			c.currentStep = Step4
			return nil, Step4, err
		}
	}

	if _, ok := pag.(*respOtherIPAndPort); ok {
		if c.currentStep == Step2 {
			ntype = enode.NATNone
			return &ntype, Step6, nil
		} else if c.currentStep == Step3 {
			ntype = enode.NATFull
			return &ntype, Step6, nil
		}

	}

	return &ntype, c.currentStep, fmt.Errorf("invalid respose packet")
}

func (c *NATClient) step4(conn *net.UDPConn) (*enode.NATType, StatusStep, error) {
	ntype := enode.NATUnknown
	udpaddr := c.conn.LocalAddr().(*net.UDPAddr)

	req := reqExternalIP{
		Version: Version,
		From:    rpcEndpoint{IP: udpaddr.IP, UDP: uint(udpaddr.Port)},
		To:      rpcEndpoint{IP: c.slave.IP, UDP: uint(c.slave.Port)},
	}

	_, err := c.send(conn, false, c.slave, reqExternalIPPacket, &req)
	if err != nil {
		log.Error("setp4", "send to slave err", err)
		return &ntype, c.currentStep, err
	}

	pag, err := readPacket(conn)
	if err != nil {
		log.Error("setp4", "read to slave", err)
		return &ntype, c.currentStep, err
	}
	if resp, ok := pag.(*respExternalIP); ok {
		if resp.External.IP.Equal(c.externalRPC.IP) && resp.External.UDP == c.externalRPC.UDP {
			nt, err := c.step5(conn)
			if c.currentStep == Step6 {
				return nt, c.currentStep, err
			} else if err != nil {
				return &ntype, Step5, err
			} else {
				return nt, c.currentStep, nil
			}
		} else {
			c.currentStep = Step6
			ntype = enode.NATSymmetric
			return &ntype, c.currentStep, nil
		}
	}

	return &ntype, c.currentStep, fmt.Errorf("invalid respose packet")
}

func (c *NATClient) step5(conn *net.UDPConn) (*enode.NATType, error) {
	ntype := enode.NATUnknown

	req := reqSameIPAndOtherPort{
		Version: Version,
	}

	_, err := c.send(conn, false, c.master, reqSameIPAndOtherPortPacket, &req)
	if err != nil {
		log.Error("step5", "send err", err)
		return nil, err
	}

	pag, err := readPacket(conn)
	if err != nil {
		ntype = enode.NATPortRestricted
		c.currentStep = Step6
		return &ntype, err
	}

	if _, ok := pag.(*respSameIPAndOtherPort); ok {
		ntype = enode.NATRestricted
		c.currentStep = Step6
		return &ntype, nil
	}

	return nil, fmt.Errorf("invalid respose packet")
}

//
func CheckNatTypeWithPublic(port int) (nattype enode.NATType) {
	logging.Info("start check nat type")
	nattype = enode.NATUnknown
	var client *stun.Client = nil

	if port <= 0 {
		client = stun.NewClient()
	} else {
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
		if err != nil {
			logging.Error("check nat failed", "err", err)
			return nattype
		}

		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			logging.Error("check nat failed", "err", err)
			return nattype
		}

		defer conn.Close()

		client = stun.NewClientWithConnection(conn)
	}

	client.SetServerAddr(NatPublicService)
	client.SetVerbose(false)
	client.SetVVerbose(false)

	nat, _, err := client.Discover()
	if err != nil {
		logging.Error("nat error", "err", err)
		return nattype
	}
	if nat == stun.NATUnknown || nat == stun.NATBlocked || nat == stun.NATError {
		return nattype
	}

	switch nat {
	case stun.NATNone:
		nattype = enode.NATNone
	case stun.NATFull:
		nattype = enode.NATFull
	case stun.NATRestricted:
		nattype = enode.NATRestricted
	case stun.NATPortRestricted:
		nattype = enode.NATPortRestricted
	case stun.NATSymetric:
		nattype = enode.NATSymmetric
	case stun.NATSymetricUDPFirewall:
		nattype = enode.NATSymmetricUDPFirewall
	}
	return nattype
}

func CheckNatTypeWithYou(port int) enode.NATType {

	m, err := net.ResolveUDPAddr("udp", NatMasterAddr)
	if err != nil {
		logging.Trace("setupServer", "ResolveUDPAddr err", err)
		return enode.NATUnknown
	}

	s, err := net.ResolveUDPAddr("udp", NatSlaveAddr)
	if err != nil {
		logging.Trace("setupServer", "ResolveUDPAddr err", err)
		return enode.NATUnknown
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		logging.Trace(fmt.Sprintf("Failed to generate node key: %v", err))
		return enode.NATUnknown
	}

	var client *NATClient = nil

	if port <= 0 {
		client = NewNATClient(key, m, s)
	} else {
		client = NewNATClientAssignPort(key, m, s, port)
	}

	ntype := client.Discover()

	if ntype == nil {
		return enode.NATUnknown
	}

	logging.Info("Nat OK", "port", port, "type", ntype.String())

	return *ntype
}
