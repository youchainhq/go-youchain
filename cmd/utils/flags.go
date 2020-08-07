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
	"fmt"
	"github.com/youchainhq/go-youchain/common/fdlimit"
	"io"
	"math/big"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/urfave/cli"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/node"
	"github.com/youchainhq/go-youchain/p2p/enode"
	"github.com/youchainhq/go-youchain/you"
)

var (
	youCfg  = you.NewDefaultConfig()
	nodeCfg = node.NewDefaultConfig()
)

var (
	BasicFlags = []cli.Flag{
		cli.StringFlag{Name: "datadir", Value: nodeCfg.DataDir, Destination: &nodeCfg.DataDir, Usage: "datadir"},
		cli.StringFlag{Name: "nodetype", Value: "full", Destination: &nodeCfg.NodeType, Usage: "node type (archive, full, light or ultralight)"},
		cli.Uint64Flag{Name: "networkid", Value: nodeCfg.NetworkId, Destination: &nodeCfg.NetworkId, Usage: "Network identifier (unsigned integer, 1=MainNet, 2=PubTestNet, others for specific purpose(develop, self-net etc.))"},
	}

	//miner config
	MinerFlags = []cli.Flag{
		cli.BoolFlag{Name: "mine", Destination: &nodeCfg.MiningEnabled, Usage: "enable mining, default false -> disable "},
		cli.StringFlag{Name: "valaddr", Usage: "the address representing a validator key to use", Destination: &nodeCfg.ValAddr},
		cli.StringFlag{Name: "pwd", Usage: "the password for the validator key", Destination: &nodeCfg.Password},
		cli.BoolFlag{Name: "keep", Usage: "whether to keep the validator key in plaintext ", Destination: &nodeCfg.Keep},
	}

	//consensus flags, mainly for testing or running a new chain
	ConsFlags = []cli.Flag{
		cli.IntFlag{Name: "constype", Value: 0, Destination: &nodeCfg.ConsType, Usage: "consensus type: 0 - YPOS, 1 - Solo"},
		cli.StringFlag{Name: "genesis", Usage: "Path to genesis", Destination: &nodeCfg.Genesis},
		cli.StringFlag{Name: "uconkey", Destination: &nodeCfg.UConKey},
		cli.StringFlag{Name: "blssignkey", Destination: &nodeCfg.BlsSignKey},
		cli.DurationFlag{Name: "soloblocktime", Value: 3 * time.Second, Destination: &nodeCfg.SoloBlockTime, Usage: "1s,1000ms"},
	}
)

// CheckSetGlobalCfg will check and/or set the node config according to global flags,
// and also do some initialization for some business modules,
// and then return the final node config
func CheckSetGlobalCfg(ctx *cli.Context) (*node.Config, *you.Config, error) {
	if err := SetMetricsConfig(ctx, &nodeCfg.Metrics); err != nil {
		return &nodeCfg, &youCfg, err
	}
	logging.Trace("LocalConfig", common.AsJson(nodeCfg), "<-")

	//load configuration from bootnode and merge into local config
	loadRemoteConfigWithContext(ctx, &nodeCfg)
	logging.Trace("ComposeConfig", common.AsJson(nodeCfg), "<-")

	if !nodeCfg.Type().IsValid() {
		return &nodeCfg, &youCfg, fmt.Errorf("invalid node type %q", nodeCfg.NodeType)
	}

	SetRPCConfig(ctx, &nodeCfg.RPC)
	if err := SetP2PConfig(ctx, &nodeCfg); err != nil {
		return &nodeCfg, &youCfg, err
	}
	if err := setTxPool(ctx, &youCfg.TxPool); err != nil {
		return &nodeCfg, &youCfg, err
	}

	if ctx.GlobalIsSet(RPCGlobalGasCap.Name) {
		youCfg.RPCGasCap = new(big.Int).SetUint64(ctx.GlobalUint64(RPCGlobalGasCap.Name))
	}
	if err := setPerfTuningConfig(ctx, nodeCfg.Type(), &youCfg); err != nil {
		return &nodeCfg, &youCfg, err
	}
	youCfg.DatabaseHandles = makeDatabaseHandles()
	return &nodeCfg, &youCfg, nil
}

func ParseNodes(input []string) []*enode.Node {
	urlArr := input
	nodes := make([]*enode.Node, 0, len(urlArr))
	for _, url := range urlArr {
		nd, err := enode.ParseV4(url)
		if err != nil {
			logging.Error("Bootstrap URL invalid", "enode", url, "err", err)
			continue
		}
		nodes = append(nodes, nd)
	}

	return nodes
}

// MakeConsolePreloads retrieves the absolute paths for the console JavaScript
// scripts to preload before starting.
func MakeConsolePreloads(jspath, preload string) []string {
	// Skip preloading if there's nothing to preload
	if preload == "" {
		return nil
	}
	// Otherwise resolve absolute paths and return them
	preloads := []string{}

	for _, file := range strings.Split(preload, ",") {
		preloads = append(preloads, common.AbsolutePath(jspath, strings.TrimSpace(file)))
	}
	return preloads
}

func GetId() string {
	return nodeCfg.Name
}

// CheckExclusive verifies that only a single instance of the provided flags was
// set by the user. Each flag might optionally be followed by a string type to
// specialize it further.
func CheckExclusive(ctx *cli.Context, args ...interface{}) {
	set := make([]string, 0, 1)
	for i := 0; i < len(args); i++ {
		// Make sure the next argument is a flag and skip if not set
		flag, ok := args[i].(cli.Flag)
		if !ok {
			panic(fmt.Sprintf("invalid argument, not cli.Flag type: %T", args[i]))
		}
		// Check if next arg extends current and expand its name if so
		name := flag.GetName()

		if i+1 < len(args) {
			switch option := args[i+1].(type) {
			case string:
				// Extended flag check, make sure value set doesn't conflict with passed in option
				if ctx.GlobalString(flag.GetName()) == option {
					name += "=" + option
					set = append(set, "--"+name)
				}
				// shift arguments and continue
				i++
				continue

			case cli.Flag:
			default:
				panic(fmt.Sprintf("invalid argument, not cli.Flag or string extension: %T", args[i+1]))
			}
		}
		// Mark the flag if it's set
		if ctx.GlobalIsSet(flag.GetName()) {
			set = append(set, "--"+name)
		}
	}
	if len(set) > 1 {
		Fatalf("Flags %v can't be used at the same time", strings.Join(set, ", "))
	}
}

// Fatalf formats a message to standard error and exits the program.
// The message is also printed to standard output if standard error
// is redirected to a different file.
func Fatalf(format string, args ...interface{}) {
	w := io.MultiWriter(os.Stdout, os.Stderr)
	if runtime.GOOS == "windows" {
		// The SameFile check below doesn't work on Windows.
		// stdout is unlikely to get redirected though, so just print there.
		w = os.Stdout
	} else {
		outf, _ := os.Stdout.Stat()
		errf, _ := os.Stderr.Stat()
		if outf != nil && errf != nil && os.SameFile(outf, errf) {
			w = os.Stderr
		}
	}
	fmt.Fprintf(w, "Fatal: "+format+"\n", args...)
	os.Exit(1)
}

// makeDatabaseHandles raises out the number of allowed file handles per process
// for Geth and returns half of the allowance to assign to the database.
func makeDatabaseHandles() int {
	limit, err := fdlimit.Maximum()
	if err != nil {
		Fatalf("Failed to retrieve file descriptor allowance: %v", err)
	}
	raised, err := fdlimit.Raise(uint64(limit))
	if err != nil {
		Fatalf("Failed to raise file descriptor allowance: %v", err)
	}
	return int(raised / 2) // Leave half for networking and other stuff
}
