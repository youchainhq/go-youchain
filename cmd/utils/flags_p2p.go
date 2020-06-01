// Copyright 2020 YOUCHAIN FOUNDATION LTD.
// Copyright 2016 The go-ethereum Authors
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

package utils

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/urfave/cli"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/node"
	"github.com/youchainhq/go-youchain/p2p"
	"github.com/youchainhq/go-youchain/p2p/enode"
	"github.com/youchainhq/go-youchain/p2p/nat/check"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/you"
	"sync"
)

var (
	p2pPrivateKey      string
	p2pKeyFile         string
	p2pMaxPeers        int
	p2pMaxPendingPeers int
	p2pMsgEvents       bool
	p2pNoDiscovery     bool
	p2pLoaclNet        bool

	defaultNatType   string
	natMasterAddr    string
	natSlaveAddr     string
	natPublicService string
)

var (
	P2PFlags = []cli.Flag{
		cli.StringFlag{Name: "p2p.bootnode", Usage: "P2P discovery bootstrap", Destination: &nodeCfg.P2PBootNode},
		cli.IntFlag{Name: "p2p.port", Value: params.DefaultP2PListenPort, Destination: &nodeCfg.P2pPort, Usage: fmt.Sprintf("Network listening port (default: %d)", params.DefaultP2PListenPort)},
		cli.IntFlag{Name: "p2p.discover", Value: params.DefaultP2PDiscoverPort, Destination: &nodeCfg.P2pDiscover, Usage: fmt.Sprintf("P2P discover port (default: %d)", params.DefaultP2PDiscoverPort)},
		cli.StringFlag{Name: "p2p.nodekey", Value: "", Destination: &p2pKeyFile, Usage: "P2P node key file"},
		cli.StringFlag{Name: "p2p.nodekeyhex", Value: "", Destination: &p2pPrivateKey, Usage: "P2P node key as hex (for testing)"},
		cli.IntFlag{Name: "p2p.maxpeers", Value: p2p.DefaultMaxPeers, Destination: &p2pMaxPeers, Usage: fmt.Sprintf("Maximum number of nodes that can be connected (default: %d)", p2p.DefaultMaxPeers)},
		cli.IntFlag{Name: "p2p.maxpendpeers", Value: 0, Destination: &p2pMaxPendingPeers, Usage: "Maximum number of pending connection attempts (defaults used if set to 0) (default: 0)"},
		cli.BoolFlag{Name: "p2p.msgevent", Destination: &p2pMsgEvents, Usage: "Open the node msg report(true is open, false is close)"},
		cli.BoolFlag{Name: "p2p.nodiscovery", Destination: &p2pNoDiscovery, Usage: "Disables the peer discovery mechanism (manual peer addition)"},
		cli.BoolFlag{Name: "p2p.localnet", Destination: &p2pLoaclNet, Usage: "The node runs on the local area network"},

		cli.StringFlag{Name: "nat.type", Value: "Unknown", Destination: &defaultNatType, Usage: "NAT type, vales:Unknown|None|Full|Restricted|PortRestricted|Symmetric"},
		cli.StringFlag{Name: "nat.master", Value: "42.62.25.77:45521", Usage: "NAT master server IP address and port", Destination: &natMasterAddr},
		cli.StringFlag{Name: "nat.slave", Value: "42.62.25.79:45523", Usage: "NAT slave server IP address and port", Destination: &natSlaveAddr},
		cli.StringFlag{Name: "nat.pubservice", Value: "stun.ideasip.com:3478", Destination: &natPublicService, Usage: "NAT public detection service address"},
	}
)

func SetP2PConfig(ctx *cli.Context, nodeConfig *node.Config) error {
	var (
		privateKey *ecdsa.PrivateKey
		natType    enode.NATType
		err        error
	)

	natType = enode.GetNATTypeFromString(defaultNatType)
	if natType == enode.NATUnknown {
		logging.Info("start Nat check", "p2p port", nodeCfg.P2pPort, "discover port", nodeCfg.P2pDiscover)
		natType, err = checkNatTypeLoop(nodeCfg.P2pPort, nodeCfg.P2pDiscover, false)
		if err != nil {
			logging.Error("Nat check failed", "err", err)
			return err
		}
		if natType == enode.NATUnknown {
			natType, err = checkNatTypeLoop(nodeCfg.P2pPort, nodeCfg.P2pDiscover, true)
			if err != nil {
				logging.Error("Nat check failed", "err", err)
				return err
			}
		}
	}

	logging.Info("Nat check complete", "natType", natType)

	if natType == enode.NATUnknown || natType == enode.NATSymmetricUDPFirewall {
		return errors.New("nat check fail")
	}

	if nodeConfig.P2PBootNode != "" {
		seeds := []string{nodeConfig.P2PBootNode}
		nodeConfig.P2P.BootstrapNodes = you.ParseNodes(seeds)
	}

	if p2pPrivateKey != "" {
		if privateKey, err = crypto.HexToECDSA(p2pPrivateKey); err != nil {
			return errors.New(fmt.Sprintf("get private key failed, err: %s", err))
		}

		nodeConfig.P2P.PrivateKey = privateKey
	} else if p2pKeyFile != "" {
		if privateKey, err = crypto.LoadECDSA(p2pKeyFile); err != nil {
			return errors.New(fmt.Sprintf("load private key from file failed, files: %s, err: %s", p2pKeyFile, err))
		}

		nodeConfig.P2P.PrivateKey = privateKey
	}

	nodeConfig.P2P.ListenAddr = fmt.Sprintf(":%d", nodeConfig.P2pPort)
	nodeConfig.P2P.DiscoverAddr = fmt.Sprintf(":%d", nodeConfig.P2pDiscover)
	nodeConfig.P2P.MaxPeers = p2pMaxPeers
	nodeConfig.P2P.NatType = natType            //natType
	nodeConfig.P2P.NodeType = nodeConfig.Type() //nodeType
	nodeConfig.P2P.EnableMsgEvents = p2pMsgEvents
	nodeConfig.P2P.ProtocolName = you.ProtocolName
	nodeConfig.P2P.MaxPendingPeers = p2pMaxPendingPeers
	nodeConfig.P2P.NoDiscovery = p2pNoDiscovery
	nodeConfig.P2P.LocalNet = p2pLoaclNet
	return nil
}

func checkNatTypeLoop(appPort, discoverPort int, isYou bool) (enode.NATType, error) {
	var (
		appType enode.NATType
		disType enode.NATType
	)

	check.NatPublicService = natPublicService
	check.NatMasterAddr = natMasterAddr
	check.NatSlaveAddr = natSlaveAddr

	check := func(port int) enode.NATType {
		if isYou {
			return check.CheckNatTypeWithYou(port)
		} else {
			return check.CheckNatTypeWithPublic(port)
		}
	}

	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		appType = check(appPort)
		disType = appType
	}()

	//go func() {
	//	defer group.Done()
	//	disType = check(discoverPort)
	//}()

	group.Wait()

	if disType != appType {
		return enode.NATUnknown, fmt.Errorf("port %d and %d have inconsistent NAT type detection. %s != %s", appPort, discoverPort, appType, disType)
	}

	return appType, nil
}
