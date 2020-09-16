/*
 * Copyright 2020 YOUCHAIN FOUNDATION LTD.
 * This file is part of the go-youchain library.
 *
 * The go-youchain library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The go-youchain library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the go-youchain library. If not, see <http://www.gnu.org/licenses/>.
 */

package utils

import (
	"github.com/urfave/cli"
	"github.com/youchainhq/go-youchain/params"
	"github.com/youchainhq/go-youchain/you"
)

var (
	cache int
)
var (
	PerfTuningFlags = []cli.Flag{
		cli.IntFlag{
			Name:        "cache",
			Usage:       "Megabytes of memory allocated to internal caching (default = 2048 for mainnet full/archive node, 512 for light node and 128 for ultralight node)",
			Value:       0,
			Destination: &cache,
		},
	}
)

func setPerfTuningConfig(ctx *cli.Context, nodeType params.NodeType, cfg *you.Config) error {
	if cache <= 0 {
		switch nodeType {
		case params.ArchiveNode:
			fallthrough
		case params.FullNode:
			cache = 2048
		case params.LightNode:
			cache = 512
		case params.UltraLightNode:
			cache = 128
		default:
			cache = 1024
		}
	}
	// set half cache to database
	cfg.DatabaseCache = cache >> 1
	return nil
}
