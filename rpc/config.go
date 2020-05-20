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

package rpc

import (
	"github.com/youchainhq/go-youchain/params"
)

var (
	DefaultConfig = &Config{
		HTTPHost:         params.DefaultHTTPHost,
		HTTPPort:         params.DefaultHTTPPort,
		HTTPCors:         []string{"*"},
		HTTPModules:      []string{"net", "you"},
		HTTPVirtualHosts: []string{"*"},
		WSHost:           params.DefaultWSHost,
		WSPort:           params.DefaultWSPort,
		WSOrigins:        []string{"*"},
		WSModules:        []string{"net", "you"},
		IPCPath:          params.DefaultIPCPath,
	}
)

type Config struct {
	HTTPHost         string   `yaml:"rpchost" json:"http_host"`
	HTTPPort         int      `yaml:"port" json:"http_port"`
	HTTPCors         []string `yaml:"rpccorsdomain" json:"http_cors"`
	HTTPVirtualHosts []string `yaml:"rpcvhosts" json:"http_vhosts"`
	HTTPModules      []string `yaml:"rpcapi" json:"http_rpcapi"`
	WSHost           string   `yaml:"wshost" json:"ws_host"`
	WSPort           int      `yaml:"wsport" json:"ws_port"`
	WSModules        []string `yaml:"wsapi" json:"ws_api"`
	WSOrigins        []string `yaml:"wsorigins" json:"ws_cors"`
	// IPCEnabled enables IPC.
	IPCEnabled bool `yaml:"ipcenabled" json:"ipc_enabled"`
	// IPCPath is the requested location to place the IPC endpoint. If the path is
	// a simple file name, it is placed inside the data directory (or on the root
	// pipe path on Windows), whereas if it's a resolvable path name (absolute or
	// relative), then that specific path is enforced.
	IPCPath string `yaml:"ipcpath" json:"ipc_path"`
}

func NewDefaultConfig() Config {
	c := *DefaultConfig
	return c
}
