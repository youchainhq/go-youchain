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

// +build !dev

package utils

import (
	"encoding/json"
	"github.com/urfave/cli"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/node"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

//todo using dev
const envSuffixHost = "_SERVICE_HOST"

func loadRemoteConfigWithContext(ctx *cli.Context, nodeConfig *node.Config) {
	bootNodeId := nodeConfig.BootNodeId

	if bootNodeId == -1 {
		bootNodeId = parseHostIdFromEnv()
	}

	bootNodeId = checkSetCiConfig(nodeConfig)

	logging.Debug("dev bootnodeid", "id", bootNodeId)
}
func checkSetCiConfig(nodeConfig *node.Config) (bootNodeId int) {
	bootNodeId = nodeConfig.BootNodeId
	if bootNodeId == -1 {
		bootNodeId = parseHostIdFromEnv()
	}

	//BootUconFile also indicates that whether it's in a CI environment.
	if bootNodeId != -1 && nodeConfig.BootUconFile != "" {
		bs, err := ioutil.ReadFile(nodeConfig.BootUconFile)
		if err == nil {
			type UconConfig struct {
				UconKey    string `json:"uconkey"`
				BlsSignKey string `json:"blssignkey,omitempty"`
			}

			var ucons []UconConfig
			err := json.Unmarshal(bs, &ucons)
			if err != nil {
				logging.Error("read uconfile", "err", err)
				return
			}

			if bootNodeId >= len(ucons) {
				logging.Error("bootNodeId exceed uconfile length", "bootNodeId", bootNodeId, "len", len(ucons))
				return
			}

			uconConfig := ucons[bootNodeId]
			nodeConfig.UConKey = uconConfig.UconKey
			nodeConfig.BlsSignKey = uconConfig.BlsSignKey
		} else {
			logging.Warn("Read BootUconFile failed", "err", err)
		}
	}

	//boot node ip
	if nodeConfig.BootNodeSvcName != "" {
		envKey := strings.ToUpper(nodeConfig.BootNodeSvcName)
		envKey = strings.ReplaceAll(envKey, "-", "_")
		envKey = envKey + envSuffixHost
		bootNodeIp, has := os.LookupEnv(envKey)
		logging.Debug("boot node ip", "env key: ", envKey, "has:", has, "value:", bootNodeIp)
		if has {
			if strings.Contains(nodeConfig.P2PBootNode, "{ip}") {
				nodeConfig.P2PBootNode = strings.Replace(nodeConfig.P2PBootNode, "{ip}", bootNodeIp, 1)
			}
		}
	}

	return bootNodeId
}

func parseHostIdFromEnv() int {
	bootNodeId := -1
	hostname := os.Getenv("HOSTNAME")
	if hostname != "" {
		parts := strings.Split(hostname, "-")
		if len(parts) >= 1 {
			id, err := strconv.ParseInt(parts[len(parts)-1], 10, 32)
			if err == nil && id >= 0 {
				bootNodeId = int(id)
			}
		}
	}
	return bootNodeId
}
