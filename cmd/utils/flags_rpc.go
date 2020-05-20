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
	"github.com/urfave/cli"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/rpc"
	"strings"
)

const (
	//flag names for some slice type
	rpcHTTPCorsFlagName         = "rpc.corsdomain"
	rpcHTTPVirtualHostsFlagName = "rpc.vhosts"
	rpcHTTPModulesFlagName      = "rpc.api"
	rpcWSModulesFlagName        = "rpc.wsapi"
	rpcWSOriginsFlagName        = "rpc.wsorigins"
)

var (
	RPCGlobalGasCap = cli.Uint64Flag{
		Name:  "rpc.gascap",
		Usage: "Sets a cap on gas that can be used in eth_call/estimateGas",
	}
	RPCFlags = []cli.Flag{
		RPCGlobalGasCap,
		cli.StringFlag{
			Name:        "rpc.host",
			Usage:       "HTTP-RPC server listening interface",
			Value:       nodeCfg.RPC.HTTPHost,
			Destination: &nodeCfg.RPC.HTTPHost,
		},
		cli.IntFlag{
			Name:        "rpc.port",
			Usage:       "HTTP-RPC server listening port",
			Value:       nodeCfg.RPC.HTTPPort,
			Destination: &nodeCfg.RPC.HTTPPort,
		},
		cli.StringFlag{
			Name:  rpcHTTPCorsFlagName,
			Usage: "Comma separated list of domains from which to accept cross origin requests (browser enforced)",
			Value: strings.Join(nodeCfg.RPC.HTTPCors, ","),
		},
		cli.StringFlag{
			Name:  rpcHTTPVirtualHostsFlagName,
			Usage: "Comma separated list of virtual hostnames from which to accept requests (server enforced). Accepts '*' wildcard.",
			Value: strings.Join(nodeCfg.RPC.HTTPVirtualHosts, ","),
		},
		cli.StringFlag{
			Name:  rpcHTTPModulesFlagName,
			Usage: "API's offered over the HTTP-RPC interface",
			Value: strings.Join(nodeCfg.RPC.HTTPModules, ","),
		},
		cli.StringFlag{
			Name:        "rpc.wshost",
			Usage:       "WS-RPC server listening interface",
			Value:       nodeCfg.RPC.WSHost,
			Destination: &nodeCfg.RPC.WSHost,
		},
		cli.IntFlag{
			Name:        "rpc.wsport",
			Usage:       "WS-RPC server listening port",
			Value:       nodeCfg.RPC.WSPort,
			Destination: &nodeCfg.RPC.WSPort,
		},
		cli.StringFlag{
			Name:  rpcWSModulesFlagName,
			Usage: "API's offered over the WS-RPC interface",
			Value: strings.Join(nodeCfg.RPC.WSModules, ","),
		},
		cli.StringFlag{
			Name:  rpcWSOriginsFlagName,
			Usage: "Origins from which to accept websockets requests",
			Value: strings.Join(nodeCfg.RPC.WSOrigins, ","),
		},
		cli.BoolFlag{
			Name:        "rpc.ipcenabled",
			Usage:       "Enable the IPC-RPC server, default is false",
			Destination: &nodeCfg.RPC.IPCEnabled,
		},
		cli.StringFlag{
			Name:        "rpc.ipcpath",
			Usage:       "ipc path, default: youchain.ipc",
			Destination: &nodeCfg.RPC.IPCPath,
		},
	}
)

// SetRPCConfig applies rpc-related command line flags to the config.
func SetRPCConfig(ctx *cli.Context, cfg *rpc.Config) {
	setHTTP(ctx, cfg)
	setWS(ctx, cfg)
	setIPC(ctx, cfg)
}

// splitAndTrim splits input separated by a comma
// and trims excessive white space from the substrings.
func splitAndTrim(input string) []string {
	result := strings.Split(input, ",")
	for i, r := range result {
		result[i] = strings.TrimSpace(r)
	}
	return result
}

// setHTTP creates the HTTP RPC listener interface string from the set
// command line flags, returning empty if the HTTP endpoint is disabled.
func setHTTP(ctx *cli.Context, cfg *rpc.Config) {
	if ctx.GlobalIsSet(rpcHTTPCorsFlagName) {
		cfg.HTTPCors = splitAndTrim(ctx.GlobalString(rpcHTTPCorsFlagName))
	}
	if ctx.GlobalIsSet(rpcHTTPModulesFlagName) {
		cfg.HTTPModules = splitAndTrim(ctx.GlobalString(rpcHTTPModulesFlagName))
	}
	if ctx.GlobalIsSet(rpcHTTPVirtualHostsFlagName) {
		cfg.HTTPVirtualHosts = splitAndTrim(ctx.GlobalString(rpcHTTPVirtualHostsFlagName))
	}
}

// setWS creates the WebSocket RPC listener interface string from the set
// command line flags, returning empty if the HTTP endpoint is disabled.
func setWS(ctx *cli.Context, cfg *rpc.Config) {
	if ctx.GlobalIsSet(rpcWSOriginsFlagName) {
		cfg.WSOrigins = splitAndTrim(ctx.GlobalString(rpcWSOriginsFlagName))
	}
	if ctx.GlobalIsSet(rpcWSModulesFlagName) {
		cfg.WSModules = splitAndTrim(ctx.GlobalString(rpcWSModulesFlagName))
	}
}

func setIPC(ctx *cli.Context, cfg *rpc.Config) {
	if cfg.IPCEnabled {
		if cfg.IPCPath == "" {
			cfg.IPCPath = params.DefaultIPCPath
		}
	} else {
		cfg.IPCPath = ""
	}
}
