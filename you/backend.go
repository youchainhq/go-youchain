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

package you

import (
	"fmt"

	"github.com/youchainhq/go-youchain/accounts"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/consensus"
	"github.com/youchainhq/go-youchain/consensus/solo"
	"github.com/youchainhq/go-youchain/consensus/ucon"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/core/bloombits"
	"github.com/youchainhq/go-youchain/crypto"
	"github.com/youchainhq/go-youchain/event"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/miner"
	"github.com/youchainhq/go-youchain/node"
	"github.com/youchainhq/go-youchain/p2p"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rpc"
	"github.com/youchainhq/go-youchain/staking"
	"github.com/youchainhq/go-youchain/you/downloader"
	"github.com/youchainhq/go-youchain/youdb"
)

const (
	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize    = 4096
	blockChanSize = 10
)

type YouChain struct {
	config     *Config
	nodeConfig *node.Config

	//channel for shutdown
	quit chan bool

	//components
	txPool     *core.TxPool
	blockChain *core.BlockChain

	miner *miner.Miner

	//DB
	chainDb youdb.Database

	accountManager *accounts.Manager

	BloomRequests chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests

	protocolManager GenericProtocolManager

	engine consensus.Engine

	stakingMan *staking.Staking

	eventMux *event.TypeMux
}

func (you *YouChain) ProtocolManager() GenericProtocolManager {
	return you.protocolManager
}

func (you *YouChain) QuitCh() <-chan bool {
	return you.quit
}

func New(config *Config, nodeConfig *node.Config) (*YouChain, error) {
	if config == nil {
		config = &DefaultConfig
	}

	if nodeConfig == nil {
		nodeConfig = &node.DefaultConfig
	}

	chainDb, err := CreateDB(nodeConfig, "chaindata", config)
	if err != nil {
		return nil, err
	}

	genesisHash, genesisErr := core.SetupGenesisBlock(chainDb, nodeConfig.NetworkId, config.Genesis)
	if genesisErr != nil {
		return nil, genesisErr
	}
	logging.Info("Initialised network configuration", "id", params.NetworkId())
	logging.Info("genesisHash", "hash", genesisHash.String())

	eventMux := event.NewMux()
	voteDb, err := CreateDB(nodeConfig, "ucondata", config)
	if err != nil {
		return nil, err
	}
	engine, err := createConsensusEngine(nodeConfig, chainDb, voteDb)
	if err != nil {
		return nil, err
	}

	you := &YouChain{
		config:        config,
		nodeConfig:    nodeConfig,
		quit:          make(chan bool),
		chainDb:       chainDb,
		engine:        engine,
		eventMux:      eventMux,
		BloomRequests: make(chan chan *bloombits.Retrieval),
	}

	you.blockChain, err = core.NewBlockChainWithType(chainDb, you.engine, eventMux, nodeConfig.Type())
	if err != nil {
		return nil, err
	}

	you.stakingMan = staking.NewStaking(eventMux)
	if nodeConfig.ConsType == node.ConsTypeYPoS {
		you.stakingMan.Register(you.blockChain.Processor())
	}

	if config.TxPool.Journal != "" {
		config.TxPool.Journal = nodeConfig.ResolvePath(config.TxPool.Journal)
	}

	you.txPool = core.NewTxPool(config.TxPool, you.blockChain)
	you.miner = miner.NewMiner(you, you.eventMux, you.engine, nodeConfig)
	err = you.initProtoMgr()

	return you, err
}

// createConsensusEngine creates the required type of consensus engine instance for an YouChain service
func createConsensusEngine(nodeConfig *node.Config, chainDb youdb.Database, voteDb youdb.Database) (engine consensus.Engine, err error) {
	switch nodeConfig.ConsType {
	case node.ConsTypeYPoS:
		//YPOS
		logging.Info("create YPoS Engine")
		engine, err = ucon.NewVRFServer(voteDb)
	case node.ConsTypeSolo:
		//Solo
		logging.Info("create FallbackSolo Engine")
		engine = solo.NewFallbackSolo(true, 0, 0, nodeConfig.SoloBlockTime)
	default:
		err = fmt.Errorf("unsupported consensus type %d", nodeConfig.ConsType)
	}
	return
}

func (you *YouChain) initProtoMgr() (err error) {
	nodeConfig := you.nodeConfig

	syncMode := downloader.ToSyncMode(nodeConfig.Type())
	if !syncMode.IsValid() {
		logging.Error("invalidate sync mode", "mode", syncMode.String())
		return err
	}
	logging.Info("Backend start with", "syncMode", syncMode.String(), "nodeType", nodeConfig.NodeType)
	if nodeConfig.ConsType == node.ConsTypeSolo || !nodeConfig.MiningEnabled {
		//Solo or not-mining
		p, err := NewProtocolManager(you.txPool, you.blockChain, you.engine, you.eventMux, you.chainDb, syncMode)
		if err != nil {
			return err
		}
		you.protocolManager = p
	} else {
		if nodeConfig.ConsType == node.ConsTypeYPoS {
			//YPOS
			uconEngine := you.engine.(consensus.Ucon)
			p, err := NewUConProtocolManager(you.txPool, you.blockChain, uconEngine, you.eventMux, you.chainDb, syncMode)
			if err != nil {
				return err
			}
			you.protocolManager = p
		}
	}
	return
}

func (you *YouChain) AccountManager() *accounts.Manager {
	return you.accountManager
}

func (you *YouChain) SetAccountManager(manager *accounts.Manager) {
	you.accountManager = manager
}

func (you *YouChain) BlockChain() *core.BlockChain {
	return you.blockChain
}

func (you *YouChain) TxPool() *core.TxPool {
	return you.txPool
}

func (you *YouChain) Miner() *miner.Miner {
	return you.miner
}

func (you *YouChain) Config() *Config {
	return you.config
}

func (you *YouChain) EventMux() *event.TypeMux { return you.eventMux }

func (you *YouChain) ChainDb() youdb.Database { return you.chainDb }

func (you *YouChain) Protocols() []p2p.Protocol {
	return you.protocolManager.GetSubProtocols()
}
func (you *YouChain) YouVersion() int {
	return int(you.protocolManager.GetSubProtocols()[0].Version)
}

func (you *YouChain) Start(server *p2p.Server) error {
	if err := you.stakingMan.Start(you.blockChain, you.engine); err != nil {
		logging.Error("start staking failed", "err", err)
		return err
	}

	you.protocolManager.Start(server, you.nodeConfig.P2P.MaxPeers)
	// Start the bloom bits servicing goroutines
	you.StartBloomHandlers(params.ACoCHTFrequency)

	if you.nodeConfig.MiningEnabled {
		//try set validator key from arguments
		ok, err := you.trySetValKeyFromConfig()
		if err != nil {
			return fmt.Errorf("set validator key error: %v", err)
		}
		if !ok {
			//try set validator using cache
			ok, err = you.trySetValKeyFromCache()
			if err != nil {
				return fmt.Errorf("set validator key error: %v", err)
			}
		}
		//if ok, then start mining; else it means not ready to mine.
		if ok {
			err = you.StartMining()
			if err != nil {
				return err
			}
		}

		// The follow logic is mainly for the need of starting a chain for test.
		if !ok {
			logging.Info("try set valkey from nodeConfig.UConKey")
			var keyStr string
			var blsKey []byte

			switch you.nodeConfig.ConsType {
			case node.ConsTypeYPoS:
				keyStr = you.nodeConfig.UConKey

				if len(keyStr) > 0 {
					if len(you.nodeConfig.BlsSignKey) == 0 {
						return fmt.Errorf("no bls secret key")
					}
					blsKey = common.FromHex(you.nodeConfig.BlsSignKey)
				}
			}

			//return quick
			if len(keyStr) == 0 {
				return fmt.Errorf("try to mine without key")
			}

			key, err := crypto.HexToECDSA(keyStr)
			if err != nil {
				return err
			}
			err = you.engine.SetValKey(key, blsKey)
			if err != nil {
				err = fmt.Errorf("set key from nodeConfig error: %v", err)
				logging.Error("SetValKey failed", "err", err)
				return err
			}
			err = you.engine.StartMining(you.blockChain, you.protocolManager, you.eventMux)
			if err != nil {
				return err
			}
			you.miner.Start()
		}
	}
	return nil
}

func (you *YouChain) trySetValKeyFromConfig() (ok bool, err error) {
	cfg := you.nodeConfig
	if cfg.ConsType == node.ConsTypeSolo {
		//Solo node, don't need to set key
		return true, nil
	}
	if len(cfg.ValAddr) > 0 {
		addr := common.HexToAddress(cfg.ValAddr)
		exist := you.accountManager.Contains(addr)
		if exist {
			err = you.UseValKey(addr, cfg.Password, cfg.Keep)
			ok = err == nil
			return
		} else {
			err = fmt.Errorf("the validator %s not exist locally", cfg.ValAddr)
			return
		}
	}
	return //default is (false,nil)
}

func (you *YouChain) trySetValKeyFromCache() (ok bool, err error) {
	key := you.accountManager.GetUnlockedValKey()
	if key != nil {
		err = you.engine.SetValKey(key.PrivateKey, key.BlsKey)
		ok = err == nil
		return
	}
	return
}

func (you *YouChain) StartMining() error {
	err := you.engine.StartMining(you.blockChain, you.protocolManager, you.eventMux)
	if err != nil {
		return err
	}
	you.miner.Start()
	return nil
}

func (you *YouChain) Stop() error {
	you.blockChain.Stop()

	you.protocolManager.Stop()

	you.txPool.Stop()
	you.miner.Close()
	you.eventMux.Stop()

	you.chainDb.Close()
	you.stakingMan.Stop()

	close(you.quit)
	return nil
}

func (you *YouChain) UseValKey(addr common.Address, password string, keep bool) error {
	key, err := you.accountManager.UseValKey(addr, password, keep)
	if err != nil {
		return err
	}
	err = you.engine.SetValKey(key.PrivateKey, key.BlsKey)
	return err
}

func (you *YouChain) APIs() []rpc.API {
	var apis []rpc.API
	return append(apis, []rpc.API{
		{
			Namespace: "miner",
			Service:   NewPrivateMinerApi(you),
			Version:   "1.0",
			Public:    false,
		},
		{
			Namespace: "you",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(you.protocolManager.Downloader(), you.eventMux),
			Public:    true,
		},
	}...)
}
