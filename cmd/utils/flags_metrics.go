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
	"github.com/urfave/cli"
	"github.com/youchainhq/go-youchain/internal/debug"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/metrics"
	"github.com/youchainhq/go-youchain/node"
	"github.com/youchainhq/go-youchain/params"
	"net/http"
	_ "net/http/pprof"
)

var (
	MetricsFlags = []cli.Flag{
		cli.BoolFlag{Name: "pprof", Destination: &nodeCfg.Metrics.PProf},
		cli.StringFlag{Name: "pprof.host", Value: params.DefaultPProfHost, Destination: &nodeCfg.Metrics.PProfHost},
		cli.IntFlag{Name: "pprof.port", Value: params.DefaultPProfPort, Destination: &nodeCfg.Metrics.PProfPort},

		cli.IntFlag{Name: "log.level", Value: int(logging.LvlInfo), Destination: &nodeCfg.LogLevel},
		cli.StringFlag{Name: "log.vmodule", Destination: &nodeCfg.LogVmodule},
		cli.StringFlag{Name: "log.path", Destination: &nodeCfg.LogPath},

		//use in metrics/metrics.go
		cli.BoolFlag{Name: "metrics", Destination: &nodeCfg.Metrics.Metrics},
		cli.BoolFlag{Name: "metrics.influxdb", Destination: &nodeCfg.Metrics.InfluxDB},
		cli.StringFlag{Name: "metrics.influxdb.hostname", Destination: &nodeCfg.Metrics.InfluxDBConfig.Hostname}, //encrypted username:password
		cli.StringFlag{Name: "metrics.influxdb.database", Destination: &nodeCfg.Metrics.InfluxDBConfig.Database}, //encrypted username:password
		cli.StringFlag{Name: "metrics.influxdb.username", Destination: &nodeCfg.Metrics.InfluxDBConfig.Username}, //plain username
		cli.StringFlag{Name: "metrics.influxdb.password", Destination: &nodeCfg.Metrics.InfluxDBConfig.Password}, //plain password
	}
)

func SetMetricsConfig(ctx *cli.Context, cfg *node.MetricsConfig) error {
	//log
	err := debug.SetupLogger(true, int(nodeCfg.LogLevel), nodeCfg.LogVmodule, nodeCfg.LogPath)
	if err != nil {
		logging.Error("SetupLogger", "error", err)
		return err
	}

	//pprof
	if cfg.PProf {
		//export with pprof end point
		metrics.Export()

		StartPProf(fmt.Sprintf("%s:%d", cfg.PProfHost, cfg.PProfPort))
	}

	//metrics
	if cfg.InfluxDB {
		tags := make(map[string]string)
		//todo identifier
		metrics.StartInfluxDB(cfg.InfluxDBConfig.Hostname, cfg.InfluxDBConfig.Database, cfg.InfluxDBConfig.Username, cfg.InfluxDBConfig.Password, tags)
	}
	return nil
}

func StartPProf(address string) {
	// Hook go-metrics into expvar on any /debug/metrics request, load all vars
	// from the registry into expvar, and execute regular expvar handler.

	logging.Info("Starting pprof server", "addr", fmt.Sprintf("http://%s/debug/pprof", address))
	go func() {
		if err := http.ListenAndServe(address, nil); err != nil {
			logging.Error("Failure in running pprof server", "err", err)
		}
	}()
}
