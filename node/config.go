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

package node

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/p2p"
	"github.com/youchainhq/go-youchain/p2p/enode"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rpc"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	datadirPrivateKey        = "nodekey"            // Path within the datadir to the node's private key
	datadirDefaultKeyStore   = "keystore"           // Path within the datadir to the keystore
	datadirStaticNodes       = "static-nodes.json"  // Path within the datadir to the static node list
	datadirTrustedNodes      = "trusted-nodes.json" // Path within the datadir to the trusted node list
	datadirNodeDatabase      = "nodes"              // Path within the datadir to store the node infos
	datadirBlacklistDatabase = "blacklist"          // Path within the datadir to store the blacklist infos
)

const (
	ConsTypeYPoS = iota
	ConsTypeSolo
)

type Config struct {
	Name      string `yaml:"name" json:"name"`
	DataDir   string `yaml:"datadir" json:"data_dir"`
	NodeType  string `yaml:"nodetype" json:"node_type"`
	NetworkId uint64 `yaml:"networkid" json:"network_id"`

	//rpc config
	RPC rpc.Config `yaml:"rpc" json:"rpc"`

	//p2p config
	P2P         p2p.Config `yaml:"p2p" json:"p2p"`
	P2PBootNode string     `yaml:"p2pbootnode" json:"p2p_bootnode"`
	P2pPort     int        `yaml:"p2pport" json:"p2p_port"`
	P2pDiscover int        `yaml:"p2pdiscover" json:"p2p_discover"`

	//miner config
	MiningEnabled bool `yaml:"mine" json:"mine"`

	//validator config
	ValAddr  string `yaml:"valaddr" json:"val_addr"`
	Password string `yaml:"-" json:"-"`
	Keep     bool   `yaml:"keep" json:"keep"` //whether to keep the validator key in plaintext

	//developer consensus config
	Genesis       string        `yaml:"genesis" json:"genesis"`
	ConsType      int           `yaml:"constype" json:"cons_type"` //consensus type: 0 - YPOS, 1 - Solo
	UConKey       string        `yaml:"uconkey" json:"ucon_key"`
	BlsSignKey    string        `yaml:"blssignkey" json:"bls_sign_key"`
	SoloBlockTime time.Duration `yaml:"soloblocktime" json:"solo_block_time"`

	//Metrics config
	Metrics MetricsConfig `yaml:"metrics" json:"metrics"`

	//DevOp config
	LogLevel   int    `yaml:"loglevel" json:"log_level"`
	LogVmodule string `yaml:"logvmodule" json:"log_vmodule"`
	LogPath    string `yaml:"logpath" json:"log_path"`
	Watch      bool   `yaml:"watch" json:"watch"` // enable watching some more detailed non-consensus data

	BootNodeId      int    `yaml:"bootnodeid" json:"boot_nodeid"`
	BootUconFile    string `yaml:"bootuconfile" json:"bootuconfile"`
	BootNodeSvcName string `yaml:"bootnodesvcname" json:"boot_node_svc_name"`

	nodeType         params.NodeType
	nodeTypeResolved bool
}

func (c *Config) ResolvePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	if c.DataDir == "" {
		return ""
	}

	return filepath.Join(c.instanceDir(), path)
}

func (c *Config) instanceDir() string {
	if c.DataDir == "" {
		return ""
	}
	return filepath.Join(c.DataDir, c.name())
}

func (c *Config) name() string {
	if c.Name == "" {
		progname := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
		if progname == "" {
			panic("empty executable name, set Config.Name")
		}
		return progname
	}
	return c.Name
}

func (c *Config) NodeKey() *ecdsa.PrivateKey {
	// Use any specifically configured key.
	if c.P2P.PrivateKey != nil {
		return c.P2P.PrivateKey
	}
	// Generate ephemeral key if no datadir is being used.
	if c.DataDir == "" {
		key, err := crypto.GenerateKey()
		logging.Info("data dir empty, generate new key")
		if err != nil {
			logging.Crit(fmt.Sprintf("Failed to generate ephemeral node key: %v", err))
		}
		return key
	}

	keyfile := c.ResolvePath(datadirPrivateKey)
	logging.Info("datadirPrivateKey", "keyfile", keyfile)
	if key, err := crypto.LoadECDSA(keyfile); err == nil {
		logging.Info("load ecdsa from file")
		return key
	}

	logging.Info("load ecdsa file failed, generate new key")

	// No persistent key found, generate and store a new one.
	key, err := crypto.GenerateKey()
	if err != nil {
		logging.Crit(fmt.Sprintf("Failed to generate node key: %v", err))
	}
	instanceDir := filepath.Join(c.DataDir, c.name())
	if err := os.MkdirAll(instanceDir, 0700); err != nil {
		logging.Error(fmt.Sprintf("Failed to persist node key: %v", err))
		return key
	}
	keyfile = filepath.Join(instanceDir, datadirPrivateKey)

	logging.Info("keyfile final", "filepath", keyfile)

	if err := crypto.SaveECDSA(keyfile, key); err != nil {
		logging.Error(fmt.Sprintf("Failed to persist node key: %v", err))
	}
	return key
}

func (c *Config) NodeDB() string {
	if c.DataDir == "" {
		return "" // ephemeral
	}
	return c.ResolvePath(datadirNodeDatabase)
}

func (c *Config) BlacklistDB() string {
	if c.DataDir == "" {
		return "" // ephemeral
	}
	return c.ResolvePath(datadirBlacklistDatabase)
}

func (c *Config) NodeName() string {
	name := c.name()
	name += "/" + runtime.GOOS + "-" + runtime.GOARCH
	name += "/" + runtime.Version()
	return name
}

func (c *Config) StaticNodes() []*enode.Node {
	return c.parsePersistentNodes(c.ResolvePath(datadirStaticNodes))
}

// TrustedNodes returns a list of node enode URLs configured as trusted nodes.
func (c *Config) TrustedNodes() []*enode.Node {
	return c.parsePersistentNodes(c.ResolvePath(datadirTrustedNodes))
}

// parsePersistentNodes parses a list of discovery node URLs loaded from a .json
// file from within the data directory.
func (c *Config) parsePersistentNodes(path string) []*enode.Node {
	// Short circuit if no node config is present
	if c.DataDir == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	// c.warnOnce(w, "Found deprecated node list file %s, please use the TOML config file instead.", path)

	// Load the nodes from the config file.
	var nodelist []string
	if err := common.LoadJSON(path, &nodelist); err != nil {
		logging.Error(fmt.Sprintf("Can't load node list file: %v", err))
		return nil
	}
	// Interpret the list as a discovery node array
	var nodes []*enode.Node
	for _, url := range nodelist {
		if url == "" {
			continue
		}
		node, err := enode.ParseV4(url)
		if err != nil {
			logging.Error(fmt.Sprintf("Node URL %s: %v\n", url, err))
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes
}

// DefaultIPCEndpoint returns the IPC path used by default.
func DefaultIPCEndpoint(clientIdentifier string) string {
	if clientIdentifier == "" {
		clientIdentifier = strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
		if clientIdentifier == "" {
			panic("empty executable name")
		}
	}
	rpccfg := rpc.NewDefaultConfig()
	rpccfg.IPCPath = clientIdentifier + ".ipc"
	config := &Config{DataDir: DefaultConfig.DataDir, RPC: rpccfg}
	return config.IPCEndpoint()
}

// IPCEndpoint resolves an IPC endpoint based on a configured value, taking into
// account the set data folders as well as the designated platform we're currently
// running on.
func (c *Config) IPCEndpoint() string {
	// Short circuit if IPC has not been enabled
	if c.RPC.IPCPath == "" {
		return ""
	}
	// On windows we can only use plain top-level pipes
	if runtime.GOOS == "windows" {
		if strings.HasPrefix(c.RPC.IPCPath, `\\.\pipe\`) {
			return c.RPC.IPCPath
		}
		return `\\.\pipe\` + c.RPC.IPCPath
	}
	// Resolve names into the data directory full paths otherwise
	if filepath.Base(c.RPC.IPCPath) == c.RPC.IPCPath {
		if c.DataDir == "" {
			return filepath.Join(os.TempDir(), c.RPC.IPCPath)
		}
		return filepath.Join(c.DataDir, c.RPC.IPCPath)
	}
	return c.RPC.IPCPath
}

// Type returns the node type
func (c *Config) Type() params.NodeType {
	if !c.nodeTypeResolved {
		if c.NodeType != "" {
			c.nodeType = params.ParseNodeType(c.NodeType)
		}
		c.nodeTypeResolved = true
	}
	return c.nodeType
}
