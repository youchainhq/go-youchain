// Copyright 2020 YOUCHAIN FOUNDATION LTD.
// This file is part of the go-youchain library.
//
// The go-youchain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-youchain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-youchain library. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"github.com/youchainhq/go-youchain/cmd/you/node"
	"github.com/youchainhq/go-youchain/logging"
	"os"
)

func main() {
	n := node.CreateNode()
	if n == nil {
		logging.Crit("start failed")
		return
	}
	err := n.Run(os.Args)
	if err != nil {
		logging.Crit("run failed", "err", err)
	}
}
