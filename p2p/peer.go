// Copyright 2014 The go-ethereum Authors
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

package p2p

import (
	"errors"
	"fmt"
	"github.com/youchainhq/go-youchain/p2p/enr"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/youchainhq/go-youchain/common"

	"github.com/youchainhq/go-youchain/common/mclock"
	"github.com/youchainhq/go-youchain/event"

	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/p2p/enode"
	"github.com/youchainhq/go-youchain/rlp"
)

var (
	ErrShuttingDown = errors.New("shutting down")
)

const (
	baseProtocolVersion    = 5
	baseProtocolLength     = uint64(16)
	baseProtocolMaxMsgSize = 2 * 1024

	readChanLen = 18

	pingInterval = 15 * time.Second
)

const (
	// devp2p message codes
	handshakeMsg = 0x00
	discMsg      = 0x01
	pingMsg      = 0x02
	pongMsg      = 0x03
)

// protoHandshake is the RLP structure of the protocol handshake.
type protoHandshake struct {
	Version    uint64
	Name       string
	Caps       []Cap
	ListenPort uint64
	ID         []byte // secp256k1 public key
	NAT        uint16
	NodeType   uint16

	// Ignore additional fields (for forward compatibility).
	Rest []rlp.RawValue `rlp:"tail"`
}

// PeerEventType is the type of peer events emitted by a p2p.Server
type PeerEventType string

const (
	// PeerEventTypeAdd is the type of event emitted when a peer is added
	// to a p2p.Server
	PeerEventTypeAdd PeerEventType = "add"

	// PeerEventTypeDrop is the type of event emitted when a peer is
	// dropped from a p2p.Server
	PeerEventTypeDrop PeerEventType = "drop"

	// PeerEventTypeMsgSend is the type of event emitted when a
	// message is successfully sent to a peer
	PeerEventTypeMsgSend PeerEventType = "msgsend"

	// PeerEventTypeMsgRecv is the type of event emitted when a
	// message is received from a peer
	PeerEventTypeMsgRecv PeerEventType = "msgrecv"

	PeerEventTypeReadChanCount PeerEventType = "chanCount"
)

// PeerEvent is an event emitted when peers are either added or dropped from
// a p2p.Server or when a message is sent or received on a peer connection
type PeerEvent struct {
	Type     PeerEventType `json:"type"`
	Peer     enode.ID      `json:"peer"`
	IP       string        `json:"ip"`
	Enode    string        `son:"Enode"`
	Error    string        `json:"error,omitempty"`
	Protocol string        `json:"protocol,omitempty"`
	MsgCode  *uint64       `json:"msg_code,omitempty"`
	MsgSize  *uint32       `json:"msg_size,omitempty"`
	Count    int           `json:"number,omitempty"`
}

// Peer represents a connected remote node.
type Peer struct {
	rw      *conn
	running map[string]*protoRW
	log     logging.Logger
	created mclock.AbsTime

	wg       sync.WaitGroup
	protoErr chan error
	closed   chan struct{}
	quit     bool
	disc     chan DiscReason

	// events receives message send / receive events if set
	events *event.Feed
}

// NewPeer returns a peer for testing purposes.
func NewPeer(id enode.ID, name string, caps []Cap, nodetype uint16) *Peer {
	//pipe, _ := net.Pipe()
	r := new(enr.Record)
	r.Set(enr.NODETYPE(nodetype))
	node := enode.SignNull(r, id)
	conn := &conn{session: nil, transport: nil, node: node, caps: caps, name: name}
	peer := newPeer(conn, nil)
	close(peer.closed) // ensures Disconnect doesn't block
	return peer
}

// ID returns the node's public key.
func (p *Peer) ID() enode.ID {
	return p.rw.node.ID()
}

// Node returns the peer's node descriptor.
func (p *Peer) Node() *enode.Node {
	return p.rw.node
}

// Name returns the node name that the remote node advertised.
func (p *Peer) Name() string {
	return p.rw.name
}

// Caps returns the capabilities (supported subprotocols) of the remote peer.
func (p *Peer) Caps() []Cap {
	// TODO: maybe return copy
	return p.rw.caps
}

// RemoteAddr returns the remote address of the network connection.
func (p *Peer) RemoteAddr() net.Addr {
	return p.rw.session.RemoteAddr()
}

// LocalAddr returns the local address of the network connection.
func (p *Peer) LocalAddr() net.Addr {
	return p.rw.session.LocalAddr()
}

// Disconnect terminates the peer connection with the given reason.
// It returns immediately and does not wait until the connection is closed.
func (p *Peer) Disconnect(reason DiscReason) {
	select {
	case p.disc <- reason:
	case <-p.closed:
	}
}

// String implements fmt.Stringer.
func (p *Peer) String() string {
	id := p.ID()
	return fmt.Sprintf("Peer %x %v", id[:8], p.RemoteAddr())
}

// Inbound returns true if the peer is an inbound connection
func (p *Peer) Inbound() bool {
	return p.rw.is(inboundConn)
}

func newPeer(conn *conn, protocols []Protocol) *Peer {

	protomap := matchProtocols(protocols, conn.caps, conn)
	p := &Peer{
		rw:       conn,
		running:  protomap,
		created:  mclock.Now(),
		disc:     make(chan DiscReason),
		protoErr: make(chan error, len(protomap)+1), // protocols + pingLoop
		closed:   make(chan struct{}),
		log:      logging.New("pid", conn.node.ID().String(), "conn", conn.flags),
		quit:     false,
	}
	return p
}

func (p *Peer) Log() logging.Logger {
	return p.log
}

func (p *Peer) run() (remoteRequested bool, err error) {
	var (
		writeStart = make(chan struct{}, 1)
		writeErr   = make(chan error, 1)
		readErr    = make(chan error, 1)
		reason     DiscReason // sent to the peer
	)
	p.wg.Add(2)
	go p.readLoop(readErr)
	go p.pingLoop()

	writeStart <- struct{}{}
	p.startProtocols(writeStart, writeErr)
	runtime := time.Now()

	// Wait for an error or disconnect.
loop:
	for {
		select {
		case err = <-writeErr:
			if err != nil {
				logging.Error("peer write failed", "err", err, "peer info", p.Info())
				reason = DiscNetworkError
				break loop
			}
			writeStart <- struct{}{}

		case err = <-readErr:
			if r, ok := err.(DiscReason); ok {
				remoteRequested = true
				reason = r
			} else {
				reason = DiscNetworkError
			}
			logging.Error("peer read failed", "err", err, "peer info", p.Info())
			break loop
		case err = <-p.protoErr:
			logging.Error("peer run protocl failed", "err", err, "peer info", p.Info())
			reason = discReasonForError(err)
			break loop
		case err = <-p.disc:
			logging.Error("peer closed by remote ", "err", err, "peer info", p.Info())
			reason = discReasonForError(err)
			break loop
		}
	}

	close(p.closed)
	p.quit = true
	p.rw.close(reason)
	p.wg.Wait()

	defer logging.Debug("peer quit", "peer:", p.Info(), " using:", time.Now().Sub(runtime), " err:", err)
	return remoteRequested, err
}

func (p *Peer) pingLoop() {
	ping := time.NewTimer(pingInterval)
	defer p.wg.Done()
	defer ping.Stop()
	for {
		select {
		case <-ping.C:
			if err := SendItems(p.rw, pingMsg); err != nil {
				p.protoErr <- err
				return
			}
			ping.Reset(pingInterval)
		case <-p.closed:
			return
		}
	}
}

func (p *Peer) readLoop(errc chan<- error) {

	defer p.wg.Done()
	for {
		if p.quit {
			return
		}
		msg, err := p.rw.ReadMsg()
		if err != nil {
			errc <- err
			return
		}

		msg.ReceivedAt = time.Now()
		if err = p.handle(msg); err != nil {
			errc <- err
			return
		}
	}
}

func (p *Peer) handle(msg Msg) error {

	switch {
	case msg.Code == pingMsg:
		msg.Discard()
		go SendItems(p.rw, pongMsg)
	case msg.Code == discMsg:
		var reason [1]DiscReason
		rlp.Decode(msg.Payload, &reason)
		return reason[0]
	case msg.Code < baseProtocolLength:
		return msg.Discard()
	default:

		proto, err := p.getProto(msg.Code)
		if err != nil {
			return fmt.Errorf("msg code out of range: %v", msg.Code)
		}

		// Msg.code needs to be offset first
		msg.Code -= proto.offset
		//Check if the message has been processed
		cache := MessageCacheInstance()
		if ok := cache.MatchFilterCode(msg.Code); ok {
			checkSum := msg.Hash()
			if cache.Check(checkSum) {
				return nil
			} else {
				cache.AddMsg(checkSum)
			}
		}

		select {
		case proto.in <- msg:
			return nil
		case <-p.closed:
			return fmt.Errorf("peer closed io.EOF")
		}
	}
	return nil
}

func countMatchingProtocols(protocols []Protocol, caps []Cap) int {
	n := 0
	for _, cap := range caps {
		for _, proto := range protocols {
			if proto.Name == cap.Name && proto.Version == cap.Version {
				n++
			}
		}
	}
	return n
}

// matchProtocols creates structures for matching named subprotocols.
func matchProtocols(protocols []Protocol, caps []Cap, rw MsgReadWriter) map[string]*protoRW {
	sort.Sort(capsByNameAndVersion(caps))
	offset := baseProtocolLength
	result := make(map[string]*protoRW)

outer:
	for _, cap := range caps {
		for _, proto := range protocols {
			if proto.Name == cap.Name && proto.Version == cap.Version {
				// If an old protocol version matched, revert it
				if old := result[cap.Name]; old != nil {
					offset -= old.Length
				}
				// Assign the new match
				result[cap.Name] = &protoRW{Protocol: proto, offset: offset, in: make(chan Msg, readChanLen), w: rw}
				offset += proto.Length

				continue outer
			}
		}
	}
	return result
}

func (p *Peer) startProtocols(writeStart <-chan struct{}, writeErr chan<- error) {
	p.wg.Add(len(p.running))
	for _, proto := range p.running {
		proto := proto
		proto.closed = p.closed
		proto.wstart = writeStart
		proto.werr = writeErr
		var rw MsgReadWriter = proto
		if p.events != nil {
			rw = newMsgEventer(rw, p.events, p, proto.Name)
		}
		p.log.Info("starting protocol", "Name", proto.Name, "Version", proto.Version)

		go func() {
			err := proto.Run(p, rw)
			if err == nil {
				p.log.Trace("Protocol returned", "Name", proto.Name, "Version", proto.Version)
				err = errProtocolReturned
			} else if err != io.EOF {
				p.log.Trace("Protocol failed", "Name", proto.Name, "Version", proto.Version, "err", err)
			}
			p.protoErr <- err
			p.wg.Done()
		}()
	}
}

// getProto finds the protocol responsible for handling
// the given message code.
func (p *Peer) getProto(code uint64) (*protoRW, error) {
	for _, proto := range p.running {
		if code >= proto.offset && code < proto.offset+proto.Length {
			return proto, nil
		}
	}
	return nil, newPeerError(errInvalidMsgCode, "%d", code)
}

type protoRW struct {
	Protocol
	in     chan Msg        // receives read messages
	closed <-chan struct{} // receives when peer is shutting down
	wstart <-chan struct{} // receives when write may start
	werr   chan<- error    // for write results
	offset uint64          // protocol offset
	w      MsgWriter
}

func (rw *protoRW) WriteMsg(msg Msg) (err error) {
	if msg.Code >= rw.Length {
		return newPeerError(errInvalidMsgCode, "not handled. Code: 0x%x, rwLen: 0x%x", msg.Code, rw.Length)
	}

	//@wei.ni Tag data has been sent
	cache := MessageCacheInstance()
	if ok := cache.MatchFilterCode(msg.Code); ok {
		checkSum := msg.Hash()
		if ok := cache.Check(checkSum); !ok {
			cache.AddMsg(checkSum)
		}
	}
	// check first and then offset msg.code
	msg.Code += rw.offset

	select {
	case <-rw.closed:
		err = ErrShuttingDown
	case <-rw.wstart:
		err = rw.w.WriteMsg(msg)
		rw.werr <- err

	}
	return err
}

func (rw *protoRW) ReadMsg() (Msg, error) {
	select {
	case msg := <-rw.in:
		return msg, nil
	case <-rw.closed:
		return Msg{}, io.EOF
	}
}

func (rw *protoRW) Addr() common.Address {
	return rw.w.Addr()
}

// PeerInfo represents a short summary of the information known about a connected
// peer. Sub-protocol independent fields are contained and initialized here, with
// protocol specifics delegated to all connected sub-protocols.
type PeerInfo struct {
	Enode    string   `json:"enode"` // Node URL
	ID       string   `json:"id"`    // Unique node identifier
	Name     string   `json:"name"`  // Name of the node, including client type, version, OS, custom data
	Nat      string   `json:"nat"`
	NodeType string   `json:"nodeType"`
	Caps     []string `json:"caps"` // Protocols advertised by this peer
	Network  struct {
		LocalAddress  string `json:"localAddress"`  // Local endpoint of the TCP data connection
		RemoteAddress string `json:"remoteAddress"` // Remote endpoint of the TCP data connection
		Inbound       bool   `json:"inbound"`
		Trusted       bool   `json:"trusted"`
		Static        bool   `json:"static"`
	} `json:"network"`
	Protocols map[string]interface{} `json:"protocols"` // Sub-protocol specific metadata fields
}

// Info gathers and returns a collection of metadata known about a peer.
func (p *Peer) Info() *PeerInfo {
	// Gather the protocol capabilities
	var caps []string
	for _, cap := range p.Caps() {
		caps = append(caps, cap.String())
	}
	// Assemble the generic peer metadata
	info := &PeerInfo{
		Enode:     p.Node().String(),
		ID:        p.ID().String(),
		Name:      p.Name(),
		Nat:       p.Node().NAT().String(),
		NodeType:  p.Node().Nodetype().String(),
		Caps:      caps,
		Protocols: make(map[string]interface{}),
	}
	info.Network.LocalAddress = p.LocalAddr().String()
	info.Network.RemoteAddress = p.RemoteAddr().String()
	info.Network.Inbound = p.rw.is(inboundConn)
	info.Network.Trusted = p.rw.is(trustedConn)
	info.Network.Static = p.rw.is(staticDialedConn)

	// Gather all the running protocol infos
	for _, proto := range p.running {
		protoInfo := interface{}("unknown")
		if query := proto.Protocol.PeerInfo; query != nil {
			if metadata := query(p.ID()); metadata != nil {
				protoInfo = metadata
			} else {
				protoInfo = "handshake"
			}
		}
		info.Protocols[proto.Name] = protoInfo
	}
	return info
}
