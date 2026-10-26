// shield-snmp-poller polls 64-bit interface counters (IF-MIB ifXTable) over SNMPv2c and
// publishes MEASURED interface rates to Redis and ClickHouse. These exact counters are what
// upstream-utilisation and saturation alarms use; flow data is only an estimate.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"shield/collector/internal/chsink"
	"shield/collector/internal/flow"
	"shield/collector/internal/iftrack"
	"shield/collector/internal/output"
	"shield/collector/internal/redisx"
	"shield/collector/internal/snmp"
)

const (
	oidIfName      = "1.3.6.1.2.1.31.1.1.1.1."
	oidHCInOctets  = "1.3.6.1.2.1.31.1.1.1.6."
	oidHCInUcast   = "1.3.6.1.2.1.31.1.1.1.7."
	oidHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10."
	oidHCOutUcast  = "1.3.6.1.2.1.31.1.1.1.11."
	oidHighSpeed   = "1.3.6.1.2.1.31.1.1.1.15."
	oidOperStatus  = "1.3.6.1.2.1.2.2.1.8."
)

type Target struct {
	Name       string   `json:"name"`
	Address    string   `json:"address"` // host or host:port
	Community  string   `json:"community"`
	Interfaces []uint32 `json:"if_indexes"`
}

type Config struct {
	IntervalSeconds int      `json:"interval_seconds"`
	TimeoutMs       int      `json:"timeout_ms"`
	Targets         []Target `json:"targets"`
	Redis           struct {
		Addr     string `json:"addr"`
		Password string `json:"password"`
	} `json:"redis"`
	ClickHouse struct {
		Enabled  bool   `json:"enabled"`
		URL      string `json:"url"`
		Database string `json:"database"`
		User     string `json:"user"`
		Password string `json:"password"`
	} `json:"clickhouse"`
}

func main() {
	path := flag.String("config", "/etc/crapplet-shield/snmp-poller.json", "config file")
	once := flag.Bool("once", false, "poll twice (to compute a rate), print results and exit")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := load(*path)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	rds := &redisx.Client{Addr: cfg.Redis.Addr, Password: cfg.Redis.Password}
	var ch *chsink.Sink
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if cfg.ClickHouse.Enabled {
		ch = chsink.New(chsink.Config{URL: cfg.ClickHouse.URL, Database: cfg.ClickHouse.Database,
			User: cfg.ClickHouse.User, Password: cfg.ClickHouse.Password, Interval: 10 * time.Second})
		go ch.Run(ctx)
	}
	tr := iftrack.New()
	tr.MinInterval = 0
	interval := time.Duration(cfg.IntervalSeconds) * time.Second
	for round := 0; ; round++ {
		var wg sync.WaitGroup
		for _, t := range cfg.Targets {
			wg.Add(1)
			go func(t Target) {
				defer wg.Done()
				rates, err := poll(t, cfg, tr)
				if err != nil {
					log.Warn("poll failed", "target", t.Name, "err", err)
					return
				}
				for _, r := range rates {
					j, _ := json.Marshal(r)
					if *once && round > 0 {
						fmt.Println(string(j))
					}
					if _, err := rds.Pipeline([][]string{{"HSET", output.KeyIfaces, r.Key(), string(j)}}); err != nil {
						log.Warn("redis", "err", err)
					}
					if ch != nil {
						ch.Add("iface_1s", output.IfaceRow{TS: time.Unix(r.TS, 0).UTC().Format("2006-01-02 15:04:05"),
							Agent: r.AgentStr, IfIndex: r.IfIndex, IfName: r.IfName, InBPS: r.InBps, OutBPS: r.OutBps,
							InPPS: r.InPps, OutPPS: r.OutPps, Speed: r.SpeedBps, Source: "snmp"})
					}
				}
			}(t)
		}
		wg.Wait()
		if *once && round > 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func poll(t Target, cfg *Config, tr *iftrack.Tracker) ([]iftrack.Rate, error) {
	host := t.Address
	ap, err := netip.ParseAddrPort(host)
	if err != nil {
		a, aerr := netip.ParseAddr(host)
		if aerr != nil {
			return nil, fmt.Errorf("address %q: %w", host, aerr)
		}
		ap = netip.AddrPortFrom(a, 161)
	}
	c := &snmp.Client{Target: ap.String(), Community: t.Community, Retries: 1,
		Timeout: time.Duration(cfg.TimeoutMs) * time.Millisecond}
	var out []iftrack.Rate
	for _, idx := range t.Interfaces {
		s := fmt.Sprint(idx)
		oids := []string{oidIfName + s, oidHCInOctets + s, oidHCInUcast + s, oidHCOutOctets + s,
			oidHCOutUcast + s, oidHighSpeed + s, oidOperStatus + s}
		v, err := c.Get(oids)
		now := time.Now()
		if err != nil {
			return out, err
		}
		if v[oidHCInOctets+s].Missing() {
			return out, fmt.Errorf("ifIndex %d has no 64-bit counters (ifXTable)", idx)
		}
		ic := flow.IfCounters{Agent: ap.Addr(), IfIndex: idx,
			SpeedBps: v[oidHighSpeed+s].Uint * 1_000_000, OperUp: v[oidOperStatus+s].Uint == 1,
			InOctets: v[oidHCInOctets+s].Uint, OutOctets: v[oidHCOutOctets+s].Uint,
			InPkts: v[oidHCInUcast+s].Uint, OutPkts: v[oidHCOutUcast+s].Uint}
		if r, ok := tr.Update(ic, now, "snmp", string(v[oidIfName+s].Bytes)); ok {
			out = append(out, r)
		}
	}
	return out, nil
}

func load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{IntervalSeconds: 10, TimeoutMs: 2000}
	c.Redis.Addr = "127.0.0.1:6379"
	c.ClickHouse.URL = "http://127.0.0.1:8123"
	c.ClickHouse.Database = "shield"
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	if c.IntervalSeconds < 5 {
		return nil, fmt.Errorf("interval_seconds must be >= 5")
	}
	if pw := os.Getenv("SHIELD_REDIS_PASSWORD"); pw != "" {
		c.Redis.Password = pw
	}
	for _, t := range c.Targets {
		if t.Community == "" || t.Community == "public" {
			return nil, fmt.Errorf("target %s: set a non-default read-only community", t.Name)
		}
	}
	return c, nil
}
