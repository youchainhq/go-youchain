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
	"fmt"
	"github.com/youchainhq/go-youchain/internal/youapi"
	"io/ioutil"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/youchainhq/go-youchain/params"

	"github.com/urfave/cli"
	"github.com/youchainhq/go-youchain/accounts"
	"github.com/youchainhq/go-youchain/accounts/keystore"
	"github.com/youchainhq/go-youchain/cmd/utils"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/internal/debug"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/node"
	"github.com/youchainhq/go-youchain/you"
	"github.com/youchainhq/go-youchain/you/gasprice"
)

var (
	banner = `
+--------------------------+
|                          |
|                          |
|         YOUChain         |
|                          |
|                          |
+--------------------------+`
	ScryptN = keystore.StandardScryptN
	ScryptP = keystore.StandardScryptP
)

func checkSetGlobalCfg(context *cli.Context) (*node.Config, *you.Config, error) {
	logging.Info("Description", "desc", context.App.Description)
	var err error
	nodeConfig, youConfig, err := utils.CheckSetGlobalCfg(context)
	if err != nil {
		return nil, nil, err
	}

	logging.Infof("you config %p %p content: %+v", youConfig, &youConfig.TxPool, youConfig.TxPool)

	if len(nodeConfig.Genesis) > 0 {
		genesis := &core.Genesis{}
		genesisFile := nodeConfig.Genesis
		logging.Info("load genesis", "file", genesisFile)
		bs, err := ioutil.ReadFile(genesisFile)
		if err != nil {
			logging.Error("genesis", "err", err)
			return nil, nil, err
		}

		err = genesis.UnmarshalJSON(bs)
		if err != nil {
			logging.Error("genesis unmarshal", "err", err)
			return nil, nil, err
		}
		youConfig.Genesis = genesis
	}

	// If user provided a genesis setting, use the networkId from the genesis
	if youConfig.Genesis != nil {
		if youConfig.NetworkId > 0 {
			nodeConfig.NetworkId = youConfig.Genesis.NetworkId
		} else {
			return nil, nil, core.ErrGenesisNoNetworkId
		}
	}
	youConfig.NetworkId = nodeConfig.NetworkId

	logging.Debug("FinalConfig", common.AsJson(nodeConfig), "<-")
	logging.Debug("FinalYouConfig", common.AsJson(youConfig), "<-")
	return nodeConfig, youConfig, nil
}

func CreateNode() *cli.App {
	app := cli.NewApp()
	app.Usage = "The YOUChain client application"
	app.Version = params.ClientVersion()
	app.Description = fmt.Sprintf("Branch: %s Revision: %s BuildTime: %s", buildBranch, revision, buildTime)

	//default main action
	app.Action = YouMain

	flags := make([]cli.Flag, 0, 80)
	flags = append(flags, utils.BasicFlags...)
	flags = append(flags, utils.MinerFlags...)
	flags = append(flags, utils.ConsFlags...)
	flags = append(flags, utils.P2PFlags...)
	flags = append(flags, utils.RPCFlags...)
	flags = append(flags, utils.DevOpFlags...)
	flags = append(flags, utils.MetricsFlags...)
	flags = append(flags, utils.TxPoolFlags...)
	flags = append(flags, utils.PerfTuningFlags...)
	app.Flags = flags

	app.Commands = cli.Commands{
		descriptionCommand,
		consoleCommand,
		attachCommand,
		checkGenesisCommand,
	}

	return app
}

func YouMain(ctx *cli.Context) error {
	nodeConfig, youConfig, err := checkSetGlobalCfg(ctx)
	if err != nil {
		return err
	}

	//region start node
	stack := MakeFullNode(youConfig, nodeConfig)
	StartNode(stack)
	stack.Wait()
	//endregion
	return nil
}

func GetId(nodeConfig *node.Config) string {
	return nodeConfig.Name
}

func StartNode(stack *node.Node) {
	if err := stack.Start(); err != nil {
		logging.Crit("Error starting protocol stack", "err", err)
	}
	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigc)
		interrupt := <-sigc

		logging.Info("Got interrupt, shutting down...", "signal", interrupt.String())
		errc := make(chan error, 1)
		go func() {
			errc <- stack.Stop()
		}()

		for i := 10; i > 0; i-- {
			<-sigc
			if i > 1 {
				logging.Info("Already shutting down, interrupt more to panic.", "times", i-1)
			}
		}

		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case err := <-errc:
			if err != nil {
				logging.Error("stack stop", "err", err)
			} else {
				logging.Info("stack stop success")
			}
		case <-timer.C:
			logging.Warn("stack stop timeout")
		}
		debug.Exit()
		debug.LoudPanic("boom")
	}()
}

func MakeFullNode(config *you.Config, nodeConfig *node.Config) *node.Node {
	stack, err := node.New(nodeConfig)
	if err != nil {
		logging.Error("create node", "err", err)
		os.Exit(1)
	}

	err = stack.Register(func(ctx *node.ServiceContext) (node.Service, error) {
		return runYc(config, nodeConfig, stack)
	})

	if err != nil {
		logging.Warn("register node", "err", err)
	}

	return stack
}

func runYc(config *you.Config, nodeConfig *node.Config, node *node.Node) (node.Service, error) {
	logging.Info(banner)
	keyStoreDir := filepath.Join(nodeConfig.DataDir, "keystore")
	ks, err := keystore.NewPassphraseKeyStore(keyStoreDir, ScryptN, ScryptP)
	if err != nil {
		logging.Error("keystore", "err", err)
		return nil, err
	}
	youChain, err := you.New(config, nodeConfig)
	if err != nil {
		logging.Error("you.new", "err", err)
		return nil, err
	}
	accountManager, err := accounts.NewManager(ks, youChain.BlockChain().CurrentBlock().Number())
	if err != nil {
		logging.Error("accountmanager", "error", err)
		return nil, err
	}
	youChain.SetAccountManager(accountManager)

	container := youapi.NewContainer(youChain, accountManager, node)

	if config.MinerGasPrice == nil || config.MinerGasPrice.Cmp(common.Big0()) <= 0 {
		logging.Warn("Sanitizing invalid miner gas price", "provided", config.MinerGasPrice, "updated", you.DefaultConfig.MinerGasPrice)
		config.MinerGasPrice = new(big.Int).Set(you.DefaultConfig.MinerGasPrice)
	}

	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.MinerGasPrice
	}
	container.Gpo = gasprice.NewOracle(container, gpoParams)
	apis := youapi.GetAPIs(container)
	apis = append(apis, youChain.APIs()...)
	apis = append(apis, node.APIs()...)
	if rpcErr := node.StartRPC(apis); rpcErr != nil {
		logging.Error("start rpc failed", "err", rpcErr)
	}

	return youChain, err
}
