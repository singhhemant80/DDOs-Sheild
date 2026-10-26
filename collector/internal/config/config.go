// Package config loads the collector's JSON configuration.
package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
)

type Exporter struct {
	Address string `json:"address"`
	Name    string `json:"name"`
	// SamplingRate overrides what the exporter reports (0 = trust the exporter).
	// Use it for devices that sample but do not export the rate.
	SamplingRate uint32 `json:"sampling_rate"`
}

type Config struct {
	Listen struct {
		NetFlow string `json:"netflow"` // NetFlow v9 and IPFIX are auto-detected on either port
		IPFIX   string `json:"ipfix"`
		SFlow   string `json:"sflow"`
	} `json:"listen"`
	ReadBufferBytes       int        `json:"read_buffer_bytes"`
	Exporters             []Exporter `json:"exporters"`
	AllowUnknownExporters bool       `json:"allow_unknown_exporters"`
	StaticPrefixes        []string   `json:"static_prefixes"`
	Redis                 struct {
		Addr     string `json:"addr"`
		Password string `json:"password"`
		DB       int    `json:"db"`
	} `json:"redis"`
	ClickHouse struct {
		Enabled       bool    `json:"enabled"`
		URL           string  `json:"url"`
		Database      string  `json:"database"`
		User          string  `json:"user"`
		Password      string  `json:"password"`
		StoreMinPPS   float64 `json:"store_min_pps"`
		StoreRawFlows bool    `json:"store_raw_flows"`
	} `json:"clickhouse"`
	// Per-attack sources: the busiest source addresses of each busy or attacked destination,
	// stored every window_seconds in ClickHouse table src_10s.
	Sources struct {
		Enabled       bool    `json:"enabled"`
		WindowSeconds int     `json:"window_seconds"`
		Top           int     `json:"top"`
		MinPPS        float64 `json:"min_pps"` // destinations above this; any rate while under an open incident
		PerDst        int     `json:"max_per_destination"`
		Total         int     `json:"max_total"`
		ASNDB         string  `json:"asn_db"` // iptoasn.com table, refreshed daily by shield-asn-update
	} `json:"sources"`
	SpreadThresholdMs int     `json:"spread_threshold_ms"`
	MaxSpreadSeconds  int     `json:"max_spread_seconds"`
	MaxDestinations   int     `json:"max_destinations"`
	PublishTop        int     `json:"publish_top"`
	StreamMaxDsts     int     `json:"stream_max_dsts"`
	StreamMinPPS      float64 `json:"stream_min_pps"`
	QueueSize         int     `json:"queue_size"`
	MetricsListen     string  `json:"metrics_listen"`

	exporters map[netip.Addr]Exporter
}

func Default() *Config {
	c := &Config{}
	c.Listen.NetFlow = "0.0.0.0:2055"
	c.Listen.IPFIX = "0.0.0.0:4739"
	c.Listen.SFlow = "0.0.0.0:6343"
	c.ReadBufferBytes = 16 << 20
	c.Redis.Addr = "127.0.0.1:6379"
	c.ClickHouse.Enabled = true
	c.ClickHouse.URL = "http://127.0.0.1:8123"
	c.ClickHouse.Database = "shield"
	c.ClickHouse.StoreMinPPS = 10
	c.Sources.Enabled = true
	c.Sources.WindowSeconds = 10
	c.Sources.Top = 20
	c.Sources.MinPPS = 5000
	c.Sources.PerDst = 2048
	c.Sources.Total = 1_000_000
	c.Sources.ASNDB = "/var/lib/crapplet-shield/ip2asn-combined.tsv.gz"
	c.SpreadThresholdMs = 2000
	c.MaxSpreadSeconds = 120
	c.MaxDestinations = 200_000
	c.PublishTop = 50
	c.StreamMaxDsts = 5000
	c.StreamMinPPS = 1
	c.QueueSize = 65536
	c.MetricsListen = "127.0.0.1:9180"
	return c
}

func Load(path string) (*Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if pw := os.Getenv("SHIELD_REDIS_PASSWORD"); pw != "" {
		c.Redis.Password = pw
	}
	if pw := os.Getenv("SHIELD_CLICKHOUSE_PASSWORD"); pw != "" {
		c.ClickHouse.Password = pw
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	c.exporters = map[netip.Addr]Exporter{}
	for _, e := range c.Exporters {
		a, err := netip.ParseAddr(e.Address)
		if err != nil {
			return fmt.Errorf("exporter %q: %w", e.Address, err)
		}
		c.exporters[a.Unmap()] = e
	}
	if len(c.exporters) == 0 && !c.AllowUnknownExporters {
		return fmt.Errorf("no exporters configured: list router addresses under \"exporters\" " +
			"(or set allow_unknown_exporters=true in a lab)")
	}
	for _, p := range c.StaticPrefixes {
		if _, err := netip.ParsePrefix(p); err != nil {
			return fmt.Errorf("static prefix %q: %w", p, err)
		}
	}
	if c.ClickHouse.Database != "" {
		for _, r := range c.ClickHouse.Database {
			if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return fmt.Errorf("invalid clickhouse database name")
			}
		}
	}
	return nil
}

// Exporter returns the configured exporter and whether packets from it are accepted.
func (c *Config) Exporter(a netip.Addr) (Exporter, bool) {
	e, ok := c.exporters[a.Unmap()]
	if ok {
		return e, true
	}
	return Exporter{Address: a.String()}, c.AllowUnknownExporters
}

func (c *Config) Prefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range c.StaticPrefixes {
		out = append(out, netip.MustParsePrefix(p).Masked())
	}
	return out
}
