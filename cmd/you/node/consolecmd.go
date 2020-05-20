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
	"github.com/youchainhq/go-youchain/core"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/youdb"
	"io/ioutil"
	"runtime"

	"github.com/urfave/cli"
	"github.com/youchainhq/go-youchain/cmd/utils"
	"github.com/youchainhq/go-youchain/console"
	"github.com/youchainhq/go-youchain/node"
	"github.com/youchainhq/go-youchain/rpc"
)

const (
	clientIdentifier = "youchain" // Client identifier to advertise over the network
)

var (
	jspath       string
	execScript   string
	preload      string
	consoleFlags = []cli.Flag{
		cli.StringFlag{Name: "jspath", Value: ".", Usage: "JavaScript root path for `loadScript`", Destination: &jspath},
		cli.StringFlag{Name: "exec", Usage: "Execute JavaScript statement", Destination: &execScript},
		cli.StringFlag{Name: "preload", Usage: "Comma separated list of JavaScript files to preload into the console", Destination: &preload},
	}

	descriptionCommand = cli.Command{
		Name:     "desc",
		Usage:    "show description",
		Category: "CONSOLE COMMANDS",
		Action: func(ctx *cli.Context) {
			fmt.Printf("Branch: %s\nRevision: %s\nBuildTime: %s \nGo revision: %s\n", buildBranch, revision, buildTime, runtime.Version())
		},
	}

	consoleCommand = cli.Command{
		Action:    localConsole,
		Name:      "console",
		Usage:     "Start an interactive JavaScript environment",
		UsageText: "you [global options] console [command options]\nFor information of global options, see `you help`",
		Flags:     consoleFlags,
		Category:  "CONSOLE COMMANDS",
		Description: `
The Youchain console is an interactive shell for the JavaScript runtime environment
which exposes a node admin interface as well as the Ðapp JavaScript API.`,
	}

	attachCommand = cli.Command{
		Action:    remoteConsole,
		Name:      "attach",
		Usage:     "Start an interactive JavaScript environment (connect to node)",
		ArgsUsage: "[endpoint]",
		Flags:     consoleFlags,
		Category:  "CONSOLE COMMANDS",
		Description: `
The You console is an interactive shell for the JavaScript runtime environment
which exposes a node admin interface as well as the Ðapp JavaScript API.
This command allows to open a console on a running youchain node.`,
	}

	checkGenesisCommand = cli.Command{
		Action:    checkGenesis,
		Name:      "check_genesis",
		Usage:     "export block hash from genesis file",
		ArgsUsage: "path/to/genesis.json",
		Category:  "CONSOLE COMMANDS",
	}
)

// localConsole starts a new YouChain node, attaching a JavaScript console to it at the
// same time.
func localConsole(c *cli.Context) error {
	nodeConfig, youConfig, err := checkSetGlobalCfg(c)
	if err != nil {
		return err
	}
	//Force to enable IPC-RPC server
	if nodeConfig.RPC.IPCPath == "" {
		nodeConfig.RPC.IPCPath = params.DefaultIPCPath
	}
	// Create and start the node based on the CLI flags
	stack := MakeFullNode(youConfig, nodeConfig)
	StartNode(stack)

	// Attach to the newly started node and start the JavaScript console
	client, err := stack.Attach()
	if err != nil {
		logger.Error("Failed to attach to the inproc youchain", "err", err)
		return err
	}
	config := console.Config{
		DataDir: nodeConfig.DataDir,
		DocRoot: jspath,
		Client:  client,
		Preload: utils.MakeConsolePreloads(jspath, preload),
	}

	console, err := console.New(config)
	if err != nil {
		logger.Error("Failed to start the JavaScript console", "err", err)
		return err
	}
	defer func() { _ = console.Stop(false) }()

	// If only a short execution was requested, evaluate and return
	if execScript != "" {
		_ = console.Evaluate(execScript)
		return nil
	}
	// Otherwise print the welcome screen and enter interactive mode
	console.Welcome()
	console.Interactive()

	return nil
}

// remoteConsole will connect to a remote YouChain instance, attaching a JavaScript
// console to it.
func remoteConsole(ctx *cli.Context) error {
	// Attach to a remotely running YouChain instance and start the JavaScript console
	nodeConfig := node.NewDefaultConfig()
	endpoint := ctx.Args().First()
	if endpoint == "" {
		path := nodeConfig.DataDir
		endpoint = fmt.Sprintf("%s/%s", path, params.DefaultIPCPath)
	}
	logger.Debug("try to dial ipc endpoint", "endpoint", endpoint)
	client, err := dialRPC(endpoint)
	if err != nil {
		logger.Error("Unable to attach to remote YOUChain", "err", err)
		return err
	}
	config := console.Config{
		DataDir: nodeConfig.DataDir,
		DocRoot: jspath,
		Client:  client,
		Preload: utils.MakeConsolePreloads(jspath, preload),
	}

	console, err := console.New(config)
	if err != nil {
		logger.Error("Failed to start the JavaScript console", "err", err)
		return err
	}
	defer func() { _ = console.Stop(false) }()

	if execScript != "" {
		_ = console.Evaluate(execScript)
		return nil
	}

	// Otherwise print the welcome screen and enter interactive mode
	console.Welcome()
	console.Interactive()

	return nil
}

// dialRPC returns a RPC client which connects to the given endpoint.
// The check for empty endpoint implements the defaulting logic
// for "you attach" with no argument.
func dialRPC(endpoint string) (*rpc.Client, error) {
	if endpoint == "" {
		endpoint = node.DefaultIPCEndpoint(clientIdentifier)
	}
	return rpc.Dial(endpoint)
}

func checkGenesis(ctx *cli.Context) error {
	genesisFile := ctx.Args().First()
	genesis := &core.Genesis{}
	bs, err := ioutil.ReadFile(genesisFile)
	if err != nil {
		logger.Error("read genesis failed", "err", err)
		return err
	}

	err = genesis.UnmarshalJSON(bs)
	if err != nil {
		logger.Error("genesis unmarshal failed", "err", err)
		return err
	}

	mem := youdb.NewMemDatabase()
	genesisBlock := genesis.ToBlock(mem)
	genesisBlockHash := genesisBlock.Hash().String()
	fmt.Println(genesisBlockHash)
	return nil
}
