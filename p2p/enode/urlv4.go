// Copyright 2018 The go-ethereum Authors
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

package enode

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"

	"github.com/youchainhq/go-youchain/common/math"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/p2p/enr"
)

var incompleteNodeURL = regexp.MustCompile("(?i)^(?:enode://)?([0-9a-f]+)$")

// MustParseV4 parses a node URL. It panics if the URL is not valid.
func MustParseV4(rawurl string) *Node {
	n, err := ParseV4(rawurl)
	if err != nil {
		panic("invalid node URL: " + err.Error())
	}
	return n
}

// ParseV4 parses a node URL.
//
// There are two basic forms of node URLs:
//
//   - incomplete nodes, which only have the public key (node ID)
//   - complete nodes, which contain the public key and IP/Port information
//
// For incomplete nodes, the designator must look like one of these
//
//    enode://<hex node id>
//    <hex node id>
//
// For complete nodes, the node ID is encoded in the username portion
// of the URL, separated from the host by an @ sign. The hostname can
// only be given as an IP address, DNS domain names are not allowed.
// The port in the host name section is the TCP listening port. If the
// TCP and UDP (discovery) ports differ, the UDP port is specified as
// query parameter "discport".
//
// In the following example, the node URL describes
// a node with IP address 10.3.58.6, RUDP listening port 9283
// and UDP discovery port 9284.
//
//    enode://<hex node id>@10.3.58.6:9283?discport=9284?nat=1?nodetype=1
func ParseV4(rawurl string) (*Node, error) {
	if m := incompleteNodeURL.FindStringSubmatch(rawurl); m != nil {
		id, err := parsePubkey(m[1])
		if err != nil {
			return nil, fmt.Errorf("invalid node ID (%v)", err)
		}
		return NewV4(id, nil, 0, 0, 0, 0), nil
	}
	return parseComplete(rawurl)
}

// NewV4 creates a node from discovery v4 node information. The record
// contained in the node has a zero-length signature.
func NewV4(pubkey *ecdsa.PublicKey, ip net.IP, rudp, udp int, nat uint16, nodetype uint16) *Node {
	var r enr.Record
	if ip != nil {
		r.Set(enr.IP(ip))
	}
	if udp != 0 {
		r.Set(enr.UDP(udp))
	}
	if rudp != 0 {
		r.Set(enr.RUDP(rudp))
	}
	if nat >= 0 && nat <= 7 {
		r.Set(enr.NAT(nat))
	} else {
		r.Set(enr.NAT(0))
	}

	//@matt add nodetype part
	if nodetype >= uint16(0) && nodetype <= 4 {
		r.Set(enr.NODETYPE(nodetype))
	} else {
		r.Set(enr.NODETYPE(uint16(0)))
	}

	signV4Compat(&r, pubkey)
	n, err := New(v4CompatID{}, &r)
	if err != nil {
		panic(err)
	}
	return n
}

func parseComplete(rawurl string) (*Node, error) {
	var (
		id                *ecdsa.PublicKey
		ip                net.IP
		rudpPort, udpPort uint64
	)
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "enode" {
		return nil, errors.New("invalid URL scheme, want \"enode\"")
	}
	// Parse the Node ID from the user portion.
	if u.User == nil {
		return nil, errors.New("does not contain node ID")
	}
	if id, err = parsePubkey(u.User.String()); err != nil {
		return nil, fmt.Errorf("invalid node ID (%v)", err)
	}
	// Parse the IP address.
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid host: %v", err)
	}
	if ip = net.ParseIP(host); ip == nil {
		return nil, errors.New("invalid IP address")
	}
	// Ensure the IP is 4 bytes long for IPv4 addresses.
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}
	// Parse the port numbers.
	if rudpPort, err = strconv.ParseUint(port, 10, 16); err != nil {
		return nil, errors.New("invalid port")
	}
	udpPort = rudpPort
	qv := u.Query()
	if qv.Get("discport") != "" {
		udpPort, err = strconv.ParseUint(qv.Get("discport"), 10, 16)
		if err != nil {
			return nil, errors.New("invalid discport in query")
		}
	}

	var nat uint64 = 0
	if qv.Get("nat") != "" {
		nat, err = strconv.ParseUint(qv.Get("nat"), 10, 16)
		if err != nil {
			return nil, errors.New("invalid nat in query")
		}
	}

	var nodetype uint64 = 0
	if qv.Get("nodetype") != "" {
		nodetype, err = strconv.ParseUint(qv.Get("nodetype"), 10, 16)
		if err != nil {
			return nil, errors.New("invalid nodetype in query")
		}
	}

	if rudpPort == udpPort {
		udpPort = rudpPort + 1
	}
	return NewV4(id, ip, int(rudpPort), int(udpPort), uint16(nat), uint16(nodetype)), nil
}

// parsePubkey parses a hex-encoded secp256k1 public key.
func parsePubkey(in string) (*ecdsa.PublicKey, error) {
	b, err := hex.DecodeString(in)
	if err != nil {
		return nil, err
	} else if len(b) != 64 {
		return nil, fmt.Errorf("wrong length, want %d hex chars", 128)
	}
	b = append([]byte{0x4}, b...)
	return crypto.UnmarshalPubkey(b)
}

func (n *Node) v4URL() string {
	var (
		scheme enr.ID
		nodeid string
		key    ecdsa.PublicKey
	)
	n.Load(&scheme)
	n.Load((*Secp256k1)(&key))
	switch {
	case scheme == "v4" || key != ecdsa.PublicKey{}:
		nodeid = fmt.Sprintf("%x", crypto.FromECDSAPub(&key)[1:])
	default:
		nodeid = fmt.Sprintf("%s.%x", scheme, n.id[:])
	}
	u := url.URL{Scheme: "enode"}
	if n.Incomplete() {
		u.Host = nodeid
	} else {
		addr := net.UDPAddr{IP: n.IP(), Port: n.RUDP()}
		u.User = url.User(nodeid)
		u.Host = addr.String()
		if n.UDP() != n.RUDP() {
			u.RawQuery = "discport=" + strconv.Itoa(n.UDP()) + "&"
		}

		u.RawQuery += "nat=" + strconv.FormatUint(uint64(n.NAT()), 10) + "&"
		u.RawQuery += "nodetype=" + strconv.FormatUint(uint64(n.Nodetype()), 10)

	}
	return u.String()
}

// PubkeyToIDV4 derives the v4 node address from the given public key.
func PubkeyToIDV4(key *ecdsa.PublicKey) ID {
	e := make([]byte, 64)
	math.ReadBits(key.X, e[:len(e)/2])
	math.ReadBits(key.Y, e[len(e)/2:])
	return ID(crypto.Keccak256Hash(e))
}
