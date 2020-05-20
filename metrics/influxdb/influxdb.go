package influxdb

import (
	"fmt"
	"github.com/youchainhq/go-youchain/logging"
	"net/url"
	"time"

	client "github.com/influxdata/influxdb1-client/v2"
	"github.com/rcrowley/go-metrics"
)

const (
	// DefaultTimeout is the default connection timeout used to connect to an InitDefaultInfluxDB instance
	DefaultTimeout = 3 * time.Second
	PingTimeout    = 1 * time.Second
	maxPoints      = 1024
)

type reporter struct {
	reg      metrics.Registry
	interval time.Duration

	url      string
	database string
	username string
	password string
	tags     map[string]string

	timeout time.Duration
	client  client.Client
}

// InfluxDB starts a InfluxDB reporter which will post the metrics from the given registry at each d interval.
func InfluxDB(r metrics.Registry, interval time.Duration, url, database, username, password string) {
	InfluxDBWithTags(r, interval, url, database, username, password, nil)
}

// InfluxDBWithTags starts a InfluxDB reporter which will post the metrics from the given registry at each d interval with the specified tags
func InfluxDBWithTags(r metrics.Registry, interval time.Duration, addr, database, username, password string, tags map[string]string) {
	_, err := url.Parse(addr)
	if err != nil {
		logging.Error("unable to parse InfluxDB url", "addr", addr, "err", err)
		return
	}

	rep := &reporter{
		reg:      r,
		interval: interval,
		url:      addr,
		database: database,
		username: username,
		password: password,
		tags:     tags,
		timeout:  DefaultTimeout,
	}
	if err := rep.makeClient(); err != nil {
		logging.Error("unable to make InfluxDB client.", "err", err)
		return
	}

	rep.run()
}

func (r *reporter) makeClient() (err error) {
	r.client, err = client.NewHTTPClient(client.HTTPConfig{
		Addr:     r.url,
		Username: r.username,
		Password: r.password,
		Timeout:  r.timeout,
	})
	return
}

func (r *reporter) run() {
	intervalTicker := time.Tick(r.interval)
	pingTicker := time.Tick(time.Second * 5)

	for {
		select {
		case <-intervalTicker:
			if err := r.send(); err != nil {
				logging.Error("unable to send metrics to InfluxDB", "err", err)
			}
		case <-pingTicker:
			_, _, err := r.client.Ping(PingTimeout)
			if err != nil {
				logging.Error("got error while sending a ping to InfluxDB, trying to recreate client", "err", err)

				if err = r.makeClient(); err != nil {
					logging.Error("unable to make InfluxDB client", "err", err)
				}
			}
		}
	}
}

func (r *reporter) send() error {
	var pts []*client.Point

	r.reg.Each(func(name string, i interface{}) {
		now := time.Now()
		switch metric := i.(type) {
		case metrics.Counter:
			ms := metric.Snapshot()
			pt, _ := client.NewPoint(
				fmt.Sprintf("%s.count", name),
				r.tags,
				map[string]interface{}{
					"value": ms.Count(),
				},
				now,
			)
			pts = append(pts, pt)
		case metrics.Gauge:
			ms := metric.Snapshot()
			pt, _ := client.NewPoint(
				fmt.Sprintf("%s.gauge", name),
				r.tags,
				map[string]interface{}{
					"value": ms.Value(),
				},
				now,
			)
			pts = append(pts, pt)
		case metrics.GaugeFloat64:
			ms := metric.Snapshot()
			pt, _ := client.NewPoint(
				fmt.Sprintf("%s.gauge", name),
				r.tags,
				map[string]interface{}{
					"value": ms.Value(),
				},
				now,
			)
			pts = append(pts, pt)
		case metrics.Histogram:
			ms := metric.Snapshot()
			ps := ms.Percentiles([]float64{0.5, 0.75, 0.95, 0.99, 0.999, 0.9999})
			pt, _ := client.NewPoint(
				fmt.Sprintf("%s.histogram", name),
				r.tags,
				map[string]interface{}{
					"count":    ms.Count(),
					"max":      ms.Max(),
					"mean":     ms.Mean(),
					"min":      ms.Min(),
					"stddev":   ms.StdDev(),
					"variance": ms.Variance(),
					"p50":      ps[0],
					"p75":      ps[1],
					"p95":      ps[2],
					"p99":      ps[3],
					"p999":     ps[4],
					"p9999":    ps[5],
				},
				now,
			)
			pts = append(pts, pt)
		case metrics.Meter:
			ms := metric.Snapshot()
			pt, _ := client.NewPoint(
				fmt.Sprintf("%s.meter", name),
				r.tags,
				map[string]interface{}{
					"count": ms.Count(),
					"m1":    ms.Rate1(),
					"m5":    ms.Rate5(),
					"m15":   ms.Rate15(),
					"mean":  ms.RateMean(),
				},
				now,
			)
			pts = append(pts, pt)
		case metrics.Timer:
			ms := metric.Snapshot()
			ps := ms.Percentiles([]float64{0.5, 0.75, 0.95, 0.99, 0.999, 0.9999})
			pt, _ := client.NewPoint(
				fmt.Sprintf("%s.timer", name),
				r.tags,
				map[string]interface{}{
					"count":    ms.Count(),
					"max":      ms.Max(),
					"mean":     ms.Mean(),
					"min":      ms.Min(),
					"stddev":   ms.StdDev(),
					"variance": ms.Variance(),
					"p50":      ps[0],
					"p75":      ps[1],
					"p95":      ps[2],
					"p99":      ps[3],
					"p999":     ps[4],
					"p9999":    ps[5],
					"m1":       ms.Rate1(),
					"m5":       ms.Rate5(),
					"m15":      ms.Rate15(),
					"meanrate": ms.RateMean(),
				},
				now,
			)
			pts = append(pts, pt)
		}
	})

	if maxPoints < len(pts) {
		pts = pts[:maxPoints]
	}
	bps, _ := client.NewBatchPoints(client.BatchPointsConfig{Database: r.database})
	bps.AddPoints(pts)
	err := r.client.Write(bps)
	logging.Debug("Write", "db", r.database, "pts", len(pts), "err", err)
	return err
}
