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
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/youchainhq/go-youchain/common/math"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/crypto/secp256k1"
	"github.com/youchainhq/go-youchain/rlp"
	"math/big"
	"net"
)

var (
	headSpace      = make([]byte, headSize)
	Version   uint = 1
)

const (
	unknownPacket packettype = iota
	reqExternalIPPacket
	respExternalIPPacket
	reqOtherIPAndPortPacket
	respOtherIPAndPortPacket
	reqSameIPAndOtherPortPacket
	respSameIPAndOtherPortPacket
)

const (
	macSize  = 256 / 8
	sigSize  = 520 / 8
	headSize = macSize + sigSize
)

type packettype byte

func (pt *packettype) String() string {
	var name string
	switch *pt {
	case reqExternalIPPacket:
		name = "request External ip packet"
	case respExternalIPPacket:
		name = "response External ip packet"
	case reqOtherIPAndPortPacket:
		name = "request slave server packet"
	case respOtherIPAndPortPacket:
		name = "response slave server packet"
	case reqSameIPAndOtherPortPacket:
		name = "resquest master other port pakcet"
	case respSameIPAndOtherPortPacket:
		name = "response master other port pakcet"
	default:
		name = "unknown pakcet"
	}

	return name
}

type packet interface {
	handle(t interface{}, from *net.UDPAddr, fromKey encPubkey, mac []byte) (packettype, error)
	// name() string
}

func encodePacket(priv *ecdsa.PrivateKey, ptype packettype, req interface{}) (packet, hash []byte, err error) {
	b := new(bytes.Buffer)
	b.Write(headSpace)
	b.WriteByte(byte(ptype))
	if err := rlp.Encode(b, req); err != nil {
		log.Error("Can't encode packet", "err", err)
		return nil, nil, err
	}
	packet = b.Bytes()
	sig, err := crypto.Sign(crypto.Keccak256(packet[headSize:]), priv)
	if err != nil {
		log.Error("Can't sign packet", "err", err)
		return nil, nil, err
	}
	copy(packet[macSize:], sig)

	hash = crypto.Keccak256(packet[macSize:])
	copy(packet, hash)
	return packet, hash, nil
}

func decodePacket(buf []byte) (packet, encPubkey, []byte, error) {
	if len(buf) < headSize+1 {
		return nil, encPubkey{}, nil, errors.New("too small")
	}
	hash, sig, sigdata := buf[:macSize], buf[macSize:headSize], buf[headSize:]

	shouldhash := crypto.Keccak256(buf[macSize:])

	if !bytes.Equal(hash, shouldhash) {
		return nil, encPubkey{}, nil, errors.New("bad hash")
	}
	fromKey, err := recoverNodeKey(crypto.Keccak256(buf[headSize:]), sig)
	if err != nil {
		return nil, fromKey, hash, err
	}

	var req packet
	ptype := packettype(sigdata[0]) /*ptype := sigdata[0]; packettype(ptype)*/
	switch ptype {
	case reqExternalIPPacket:
		req = new(reqExternalIP)
	case respExternalIPPacket:
		req = new(respExternalIP)
	case reqOtherIPAndPortPacket:
		req = new(reqOtherIPAndPort)
	case respOtherIPAndPortPacket:
		req = new(respOtherIPAndPort)
	case reqSameIPAndOtherPortPacket:
		req = new(reqSameIPAndOtherPort)
	case respSameIPAndOtherPortPacket:
		req = new(respSameIPAndOtherPort)
	default:
		return nil, fromKey, hash, fmt.Errorf("unknown type: %d", ptype)
	}

	s := rlp.NewStream(bytes.NewReader(sigdata[1:]), 0)
	err = s.Decode(req)
	return req, fromKey, hash, err
}

type encPubkey [64]byte

func encodePubkey(key *ecdsa.PublicKey) encPubkey {
	var e encPubkey
	math.ReadBits(key.X, e[:len(e)/2])
	math.ReadBits(key.Y, e[len(e)/2:])
	return e
}

func decodePubkey(e encPubkey) (*ecdsa.PublicKey, error) {
	p := &ecdsa.PublicKey{Curve: crypto.S256(), X: new(big.Int), Y: new(big.Int)}
	half := len(e) / 2
	p.X.SetBytes(e[:half])
	p.Y.SetBytes(e[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return nil, errors.New("invalid secp256k1 curve point")
	}
	return p, nil
}

func recoverNodeKey(hash, sig []byte) (key encPubkey, err error) {
	pubkey, err := secp256k1.RecoverPubkey(hash, sig)
	if err != nil {
		return key, err
	}
	copy(key[:], pubkey[1:])
	return key, nil
}

type (
	rpcEndpoint struct {
		IP  net.IP
		UDP uint
	}

	reqExternalIP struct {
		Version  uint
		From, To rpcEndpoint
	}

	respExternalIP struct {
		Version        uint
		From, External rpcEndpoint
	}

	reqOtherIPAndPort struct {
		Version  uint
		From, To rpcEndpoint
	}

	respOtherIPAndPort struct {
		Version uint
	}

	reqSameIPAndOtherPort struct {
		Version uint
	}

	respSameIPAndOtherPort struct {
		Version uint
	}
)

func (req *reqExternalIP) handle(t interface{}, from *net.UDPAddr, fromKey encPubkey, mac []byte) (packettype, error) {
	if req.Version != Version {
		return reqExternalIPPacket, fmt.Errorf("unknown packet Version %d", req.Version)
	}

	_, err := decodePubkey(fromKey)
	if err != nil {
		return reqExternalIPPacket, fmt.Errorf("invalid public key: %s", err)
	}

	if conn, ok := t.(*NATConn); ok {
		log.Info("reqExternalIP handle", "peer ip:", from.String())
		resp := respExternalIP{
			Version:  req.Version,
			From:     rpcEndpoint{IP: conn.IP(), UDP: uint(conn.Port())},
			External: rpcEndpoint{IP: from.IP, UDP: uint(from.Port)},
		}
		_, err := conn.send(from, respExternalIPPacket, &resp)
		return reqExternalIPPacket, err
	}

	return reqExternalIPPacket, fmt.Errorf("invalid handler obj error")
}

func (resp *respExternalIP) handle(t interface{}, from *net.UDPAddr, fromKey encPubkey, mac []byte) (packettype, error) {
	return respExternalIPPacket, nil
}

func (req *reqOtherIPAndPort) handle(t interface{}, from *net.UDPAddr, fromKey encPubkey, mac []byte) (packettype, error) {
	if req.Version != Version {
		return reqOtherIPAndPortPacket, fmt.Errorf("unknown packet Version %d", req.Version)
	}

	_, err := decodePubkey(fromKey)
	if err != nil {
		return reqOtherIPAndPortPacket, fmt.Errorf("invalid public key: %s", err)
	}

	if conn, ok := t.(*NATConn); ok {
		log.Info("reqOtherIPAndPort handle", "peer reqOtherIPAndPort:", from.String())
		resp := respOtherIPAndPort{
			Version: Version,
		}
		packet, _, err := encodePacket(conn.priv, respOtherIPAndPortPacket, &resp)
		if err != nil {
			log.Error("reqOtherIPAndPort handle", "encodePachet err", err)
			return respOtherIPAndPortPacket, err
		}
		msg := message{
			to:     from,
			packet: packet,
		}

		conn.commit <- &msg
		return reqOtherIPAndPortPacket, nil
	}

	return reqOtherIPAndPortPacket, fmt.Errorf("invalid hndler obj")
}

func (respOtherIPAndPort) handle(t interface{}, from *net.UDPAddr, fromKey encPubkey, mac []byte) (packettype, error) {
	return respOtherIPAndPortPacket, nil
}

func (req *reqSameIPAndOtherPort) handle(t interface{}, from *net.UDPAddr, fromKey encPubkey, mac []byte) (packettype, error) {
	if req.Version != Version {
		return reqSameIPAndOtherPortPacket, fmt.Errorf("unknown packet Version %d", req.Version)
	}

	_, err := decodePubkey(fromKey)
	if err != nil {
		return reqSameIPAndOtherPortPacket, fmt.Errorf("invalid public key: %s", err)
	}

	if conn, ok := t.(*NATConn); ok {
		resp := respSameIPAndOtherPort{
			Version: Version,
		}
		packet, _, err := encodePacket(conn.priv, respSameIPAndOtherPortPacket, &resp)
		if err != nil {
			return reqSameIPAndOtherPortPacket, err
		}
		return reqSameIPAndOtherPortPacket, conn.DialTo(from, packet)
	}

	return reqSameIPAndOtherPortPacket, fmt.Errorf("invalid hndler obj")
}

func (resp *respSameIPAndOtherPort) handle(t interface{}, from *net.UDPAddr, fromKey encPubkey, mac []byte) (packettype, error) {
	return respSameIPAndOtherPortPacket, nil
}

/*
tcp/ip protocol pritvte net ipnet
10.0.0.0/8: 10.0.0.0 ~ 10.255.255.255
172.16.0.0/12: 172.16.0.0 ~ 172.31.255.255
192.168.0.0/16: 192.168.0.0 ~ 192.168.255.255
*/

var (
	ipnets = []ipnet{}
)

func init() {
	min := IPv4ToInt(net.ParseIP("10.0.0.0"))
	max := IPv4ToInt(net.ParseIP("10.255.255.255"))
	ipnets = append(ipnets, ipnet{min: min, max: max})

	min = IPv4ToInt(net.ParseIP("172.16.0.0"))
	max = IPv4ToInt(net.ParseIP("172.31.255.255"))
	ipnets = append(ipnets, ipnet{min: min, max: max})

	min = IPv4ToInt(net.ParseIP("192.168.0.0"))
	max = IPv4ToInt(net.ParseIP("192.168.255.255"))
	ipnets = append(ipnets, ipnet{min: min, max: max})
}

type ipnet struct {
	min int
	max int
}

func IPv4ToInt(ip net.IP) int {
	if ipv4 := ip.To4(); ipv4 != nil {
		num := 0x00000000
		num = num | (int(ipv4[0]) << 24)
		num = num | (int(ipv4[1]) << 16)
		num = num | (int(ipv4[2]) << 8)
		num = num | int(ipv4[3])
		return num
	}
	return 0
}

func IntToIPv4(num int) net.IP {
	if num > 0xFFFFFF && num <= 0 {
		return nil
	}

	a := num >> 24
	b := (num & 0x00FFFFFF) >> 16
	c := (num & 0x0000FFFF) >> 8
	d := (num & 0x000000FF)

	return net.IPv4(byte(a), byte(b), byte(c), byte(d))
}

func AssertPrivatIP(ip net.IP) bool {

	self := IPv4ToInt(ip)
	for _, v := range ipnets {
		if self >= v.min && self <= v.max {
			return true
		}
	}
	return false
}

func getLocalIPs() []*net.IPNet {
	ips := []*net.IPNet{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Error("Getlocalip", "err", err)
		return ips
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet)
			}
		}
	}

	return ips
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		log.Crit(fmt.Sprintf("Failed to generate node key: %v", err))
		return nil, err
	}

	return key, nil
}
