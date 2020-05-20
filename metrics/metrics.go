// Go port of Coda Hale's Metrics library
//
// <https://github.com/rcrowley/go-metrics>
//
// Coda Hale's original work: <https://github.com/codahale/metrics>
package metrics

import (
	"github.com/rcrowley/go-metrics/exp"
	"github.com/youchainhq/go-youchain/logging"
	"github.com/youchainhq/go-youchain/metrics/influxdb"
	"os"
	"strings"
	"time"

	"github.com/rcrowley/go-metrics"
)

const (
	interval = 5 * time.Second
	// MetricsEnabledFlag metrics enable flag
	MetricsEnabledFlag = "metrics"
)

var (
	enable = false
)

func init() {
	for _, arg := range os.Args {
		if strings.TrimLeft(arg, "-") == MetricsEnabledFlag {
			EnableMetrics()
			return
		}
	}
}

// EnableMetrics enable the metrics service
func EnableMetrics() {
	if !enable {
		enable = true
	}
}

func Export() {
	if !enable {
		return
	}
	exp.Exp(metrics.DefaultRegistry)
}

func StartInfluxDB(hostname, database, username, password string, tags map[string]string) {
	go (func() {
		influxdb.InfluxDBWithTags(metrics.DefaultRegistry, interval, hostname, database, username, password, tags)
		logging.Info("Started Influx DB Transport.")
	})()
}

// NewCounter create a new metrics Counter
func NewCounter(name string) metrics.Counter {
	if !enable {
		return new(metrics.NilCounter)
	}
	return metrics.GetOrRegisterCounter(name, metrics.DefaultRegistry)
}

// NewMeter create a new metrics Meter
func NewMeter(name string) metrics.Meter {
	if !enable {
		return new(metrics.NilMeter)
	}
	return metrics.GetOrRegisterMeter(name, metrics.DefaultRegistry)
}

func NewNilMeter() metrics.Meter {
	return new(metrics.NilMeter)
}

// NewTimer create a new metrics Timer
func NewTimer(name string) metrics.Timer {
	if !enable {
		return new(metrics.NilTimer)
	}
	return metrics.GetOrRegisterTimer(name, metrics.DefaultRegistry)
}

// NewGauge create a new metrics Gauge
func NewGauge(name string) metrics.Gauge {
	if !enable {
		return new(metrics.NilGauge)
	}
	return metrics.GetOrRegisterGauge(name, metrics.DefaultRegistry)
}

// NewHistogramWithUniformSample create a new metrics History with Uniform Sample algorithm.
func NewHistogramWithUniformSample(name string, reservoirSize int) metrics.Histogram {
	if !enable {
		return new(metrics.NilHistogram)
	}
	return metrics.GetOrRegisterHistogram(name, nil, metrics.NewUniformSample(reservoirSize))
}
