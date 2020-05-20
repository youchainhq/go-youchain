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

package mobile

import (
	"errors"
	"fmt"
	"github.com/youchainhq/go-youchain/accounts/keystore"
	"github.com/youchainhq/go-youchain/cmd/you/node"
	"github.com/youchainhq/go-youchain/common"
	"github.com/youchainhq/go-youchain/logging"
)

func Version() string {
	return fmt.Sprintf("Revision:%s Time:%s Branch:%s", version, buildTime, buildBranch)
}

type Args struct {
	args []string
}

func NewArgs() *Args {
	args := &Args{
		args: []string{},
	}
	args.args = append(args.args, "you") //placeholder required
	return args
}

func (a *Args) Add(arg string) {
	a.args = append(a.args, arg)
}

func (a *Args) toJson() string {
	return common.AsJson(a.args)
}

func (a *Args) Export() []string {
	return a.args
}

func Run(args *Args) error {
	node.ScryptN = keystore.LightScryptN
	node.ScryptP = keystore.LightScryptP

	logging.Info("start with", "cli.json", args.toJson())

	n := node.CreateNode()
	if n == nil {
		logging.Error("node start failed")
		return errors.New("node start failed")
	}

	logging.Info("node run")
	err := n.Run(args.Export())
	if err != nil {
		fmt.Println(err)
		logging.Error("Run", "err", err)
		return err
	}
	logging.Info("node exit")
	return nil
}
