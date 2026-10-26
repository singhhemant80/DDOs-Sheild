// shield-collector receives NetFlow v9 / IPFIX / sFlow v5, aggregates per protected
// destination per second, and publishes to Redis (live) and ClickHouse (history).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"shield/collector/internal/agg"
	"shield/collector/internal/chsink"
	"shield/collector/internal/config"
	"shield/collector/internal/flow"
	"shield/collector/internal/iftrack"
	"shield/collector/internal/metrics"
	"shield/collector/internal/netflow"
	"shield/collector/internal/output"
	"shield/collector/internal/prefix"
	"shield/collector/internal/redisx"
	"shield/collector/internal/sflow"
)

const version = "0.4.0"

type exporterStats struct {
	kind             atomic.Value
	packets, records atomic.Uint64
	lastSeen         atomic.Int64
	lastRate         atomic.Uint32
	name             string
	override         uint32
}

// expKey separates stats per protocol family: one router often exports NetFlow and sFlow.
type expKey struct {
	addr  netip.Addr
	proto string
}

type app struct {
	cfg       *config.Config
	log       *slog.Logger
	reg       *metrics.Registry
	prefixes  prefix.Holder
	prefixSrc atomic.Value
	nf        *netflow.Decoder
	recCh     chan []flow.Record
	ifCh      chan []flow.IfCounters
	ch        *chsink.Sink
	rds       *redisx.Client
	ift       *iftrack.Tracker
	started   time.Time

	expMu     sync.Mutex
	exporters map[expKey]*exporterStats

	queueDrops, rejected, decodeErr *atomic.Uint64
	records, packets                *atomic.Uint64
	redisErr, published             *atomic.Uint64
	dstsDropped                     atomic.Uint64
	spreadPending                   atomic.Int64
}

func main() {
	cfgPath := flag.String("config", "/etc/crapplet-shield/collector.json", "config file")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(2)
	}
	a := newApp(cfg, log)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := a.run(ctx); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func newApp(cfg *config.Config, log *slog.Logger) *app {
	reg := metrics.New()
	a := &app{
		cfg: cfg, log: log, reg: reg, nf: netflow.NewDecoder(),
		recCh:      make(chan []flow.Record, cfg.QueueSize/16+1),
		ifCh:       make(chan []flow.IfCounters, 256),
		rds:        &redisx.Client{Addr: cfg.Redis.Addr, Password: cfg.Redis.Password, DB: cfg.Redis.DB},
		ift:        iftrack.New(),
		started:    time.Now(),
		exporters:  map[expKey]*exporterStats{},
		queueDrops: reg.Counter("shield_collector_queue_drops_total", "Packets dropped because the aggregation queue was full"),
		rejected:   reg.Counter("shield_collector_rejected_packets_total", "Packets from addresses not configured as exporters"),
		decodeErr:  reg.Counter("shield_collector_decode_errors_total", "Malformed export packets"),
		records:    reg.Counter("shield_collector_records_total", "Flow records / samples decoded"),
		packets:    reg.Counter("shield_collector_packets_total", "Export packets received"),
		redisErr:   reg.Counter("shield_collector_redis_errors_total", "Failed Redis publishes"),
		published:  reg.Counter("shield_collector_published_seconds_total", "Seconds published to Redis"),
	}
	a.prefixes.Store(prefix.New(cfg.Prefixes()))
	a.prefixSrc.Store("static")
	if cfg.ClickHouse.Enabled {
		a.ch = chsink.New(chsink.Config{URL: cfg.ClickHouse.URL, Database: cfg.ClickHouse.Database,
			User: cfg.ClickHouse.User, Password: cfg.ClickHouse.Password})
		reg.GaugeFunc("shield_collector_clickhouse_pending_rows", "Rows waiting for ClickHouse",
			func() float64 { return float64(a.ch.Pending()) })
		reg.GaugeFunc("shield_collector_clickhouse_dropped_rows", "Rows dropped (buffer full)",
			func() float64 { return float64(a.ch.Dropped.Load()) })
	}
	reg.GaugeFunc("shield_collector_prefixes", "Protected prefixes loaded",
		func() float64 { return float64(a.prefixes.Load().Len()) })
	return a
}

func (a *app) run(ctx context.Context) error {
	var wg sync.WaitGroup
	listeners := []struct {
		addr string
		kind string
	}{{a.cfg.Listen.NetFlow, "netflow"}, {a.cfg.Listen.IPFIX, "netflow"}, {a.cfg.Listen.SFlow, "sflow"}}
	started := 0
	for _, l := range listeners {
		if l.addr == "" {
			continue
		}
		conn, err := a.listen(l.addr)
		if err != nil {
			return err
		}
		started++
		a.log.Info("listening", "addr", l.addr, "protocols", l.kind)
		wg.Add(1)
		go func(c *net.UDPConn, kind string) {
			defer wg.Done()
			a.receive(ctx, c, kind)
		}(conn, l.kind)
	}
	if started == 0 {
		return errors.New("no listeners configured")
	}
	if a.ch != nil {
		wg.Add(1)
		go func() { defer wg.Done(); a.ch.Run(ctx) }()
	}
	go a.refreshPrefixes(ctx)
	go a.serveMetrics()
	a.aggregate(ctx) // blocks until ctx done
	wg.Wait()
	a.rds.Close()
	a.log.Info("stopped")
	return nil
}

func (a *app) listen(addr string) (*net.UDPConn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	if err := c.SetReadBuffer(a.cfg.ReadBufferBytes); err != nil {
		a.log.Warn("could not set socket buffer; raise net.core.rmem_max", "err", err)
	}
	return c, nil
}

func (a *app) exporter(addr netip.Addr, proto string) (*exporterStats, bool) {
	a.expMu.Lock()
	defer a.expMu.Unlock()
	if s, ok := a.exporters[expKey{addr, proto}]; ok {
		return s, true
	}
	e, ok := a.cfg.Exporter(addr)
	if !ok {
		return nil, false
	}
	s := &exporterStats{name: e.Name, override: e.SamplingRate}
	a.exporters[expKey{addr, proto}] = s
	return s, true
}

func (a *app) receive(ctx context.Context, c *net.UDPConn, kind string) {
	go func() { <-ctx.Done(); c.Close() }()
	buf := make([]byte, 65535)
	var recs []flow.Record
	var ifs []flow.IfCounters
	for {
		n, src, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Warn("read", "err", err)
			continue
		}
		a.packets.Add(1)
		ip := src.Addr().Unmap()
		st, ok := a.exporter(ip, kind)
		if !ok {
			a.rejected.Add(1)
			continue
		}
		recs, ifs = recs[:0], ifs[:0]
		pkt := buf[:n]
		if kind == "sflow" {
			recs, ifs, err = sflow.Decode(ip, pkt, recs, ifs)
		} else {
			recs, err = a.nf.Decode(ip, pkt, recs)
		}
		if err != nil {
			a.decodeErr.Add(1)
		}
		st.packets.Add(1)
		st.lastSeen.Store(time.Now().Unix())
		if len(recs) > 0 {
			st.kind.Store(recs[0].Kind.String())
			st.records.Add(uint64(len(recs)))
			st.lastRate.Store(recs[len(recs)-1].SamplingRate)
			if st.override > 0 {
				for i := range recs {
					recs[i].SamplingRate = st.override
				}
			}
			a.records.Add(uint64(len(recs)))
			batch := append([]flow.Record(nil), recs...)
			select {
			case a.recCh <- batch:
			default:
				a.queueDrops.Add(1)
			}
		} else if kind == "sflow" {
			st.kind.Store("sflow")
		}
		if len(ifs) > 0 {
			select {
			case a.ifCh <- append([]flow.IfCounters(nil), ifs...):
			default:
			}
		}
	}
}

func (a *app) aggregate(ctx context.Context) {
	ag := agg.New(agg.Config{
		SpreadThreshold: time.Duration(a.cfg.SpreadThresholdMs) * time.Millisecond,
		MaxSpread:       time.Duration(a.cfg.MaxSpreadSeconds) * time.Second,
		MaxDsts:         a.cfg.MaxDestinations,
	}, &a.prefixes)
	pubCh := make(chan agg.Second, 4)
	go a.publisher(ctx, pubCh)
	// Align ticks to wall-clock second boundaries.
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	defer close(pubCh)
	for {
		select {
		case <-ctx.Done():
			return
		case batch := <-a.recCh:
			for i := range batch {
				ag.Add(&batch[i])
			}
			if a.ch != nil && a.cfg.ClickHouse.StoreRawFlows {
				now := time.Now()
				for _, r := range batch {
					a.ch.Add("flows_raw", rawRow(now, r))
				}
			}
		case ifs := <-a.ifCh:
			now := time.Now()
			for _, c := range ifs {
				if r, ok := a.ift.Update(c, now, "sflow", ""); ok {
					a.publishIface(r)
				}
			}
		case t := <-tick.C:
			// The bucket being closed is the second that just ended.
			s := ag.Tick(t.Truncate(time.Second).Add(-time.Second))
			a.dstsDropped.Store(ag.Dropped)
			a.spreadPending.Store(int64(s.SpreadPending))
			select {
			case pubCh <- s:
			default:
				a.redisErr.Add(1) // publisher is stuck; skip this second rather than stall collection
			}
		}
	}
}

func (a *app) publisher(ctx context.Context, in <-chan agg.Second) {
	lastStatus := time.Time{}
	for s := range in {
		compact, full, hist := output.Build(&s, a.cfg.PublishTop, a.cfg.StreamMaxDsts, a.cfg.StreamMinPPS)
		cj, _ := json.Marshal(compact)
		fj, _ := json.Marshal(full)
		hj, _ := json.Marshal(hist)
		cmds := [][]string{
			{"PUBLISH", output.ChanTraffic, string(cj)},
			{"SET", output.KeyLatest, string(cj), "EX", "15"},
			{"LPUSH", output.KeyHistory, string(hj)},
			{"LTRIM", output.KeyHistory, "0", strconv.Itoa(output.HistoryLen - 1)},
			{"XADD", output.StreamFull, "MAXLEN", "~", "900", "*", "d", string(fj)},
		}
		if time.Since(lastStatus) >= 5*time.Second {
			st, _ := json.Marshal(a.status())
			cmds = append(cmds, []string{"SET", output.KeyCollector, string(st), "EX", "15"})
			lastStatus = time.Now()
		}
		if _, err := a.rds.Pipeline(cmds); err != nil {
			a.redisErr.Add(1)
			a.log.Debug("redis publish", "err", err)
		} else {
			a.published.Add(1)
		}
		if a.ch != nil {
			a.ch.Add("totals_1s", output.TotalsRowOf(s.TS, "in", compact.In))
			a.ch.Add("totals_1s", output.TotalsRowOf(s.TS, "out", compact.Out))
			for _, d := range full.Dsts {
				if d.PPS >= a.cfg.ClickHouse.StoreMinPPS {
					a.ch.Add("dst_1s", output.DstRowOf(s.TS, d))
				}
			}
		}
		_ = ctx
	}
}

func (a *app) publishIface(r iftrack.Rate) {
	j, _ := json.Marshal(r)
	if _, err := a.rds.Pipeline([][]string{{"HSET", output.KeyIfaces, r.Key(), string(j)}}); err != nil {
		a.redisErr.Add(1)
	}
	if a.ch != nil {
		a.ch.Add("iface_1s", output.IfaceRow{TS: time.Unix(r.TS, 0).UTC().Format("2006-01-02 15:04:05"),
			Agent: r.AgentStr, IfIndex: r.IfIndex, IfName: r.IfName, InBPS: r.InBps, OutBPS: r.OutBps,
			InPPS: r.InPps, OutPPS: r.OutPps, Speed: r.SpeedBps, Source: r.Source})
	}
}

func rawRow(t time.Time, r flow.Record) output.RawRow {
	return output.RawRow{TS: t.UTC().Format("2006-01-02 15:04:05"), Kind: r.Kind.String(),
		Exporter: r.Exporter.String(), Src: r.Src.String(), Dst: r.Dst.String(), Proto: r.Proto,
		SrcPort: r.SrcPort, DstPort: r.DstPort, Flags: r.TCPFlags, Bytes: r.Bytes, Packets: r.Packets,
		Sampling: r.SamplingRate, Duration: r.DurationMs}
}

// refreshPrefixes loads the protected prefix list the API publishes to Redis. Static prefixes
// from the config file are always included. If Redis is unreachable the last list is kept.
func (a *app) refreshPrefixes(ctx context.Context) {
	static := a.cfg.Prefixes()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	lastLen := -1
	for {
		raw, err := a.rds.Get(output.KeyPrefixes)
		switch {
		case err == nil:
			var doc struct {
				Prefixes []string `json:"prefixes"`
			}
			if jerr := json.Unmarshal([]byte(raw), &doc); jerr != nil {
				a.log.Warn("bad prefix document in redis", "err", jerr)
				break
			}
			ps := append([]netip.Prefix(nil), static...)
			for _, s := range doc.Prefixes {
				if p, perr := netip.ParsePrefix(s); perr == nil {
					ps = append(ps, p.Masked())
				}
			}
			a.prefixes.Store(prefix.New(ps))
			a.prefixSrc.Store("api")
			if len(ps) != lastLen {
				a.log.Info("protected prefixes loaded", "count", len(ps))
				lastLen = len(ps)
			}
		case errors.Is(err, redisx.Nil):
			if lastLen != len(static) {
				a.log.Warn("no prefix list published by the API yet; using static prefixes only", "count", len(static))
				lastLen = len(static)
			}
		default:
			a.log.Warn("redis unavailable; keeping current prefix list", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *app) status() output.Status {
	st := output.Status{
		TS: time.Now().Unix(), Version: version, StartedAt: a.started.Unix(),
		Prefixes: a.prefixes.Load().Len(), PrefixSource: a.prefixSrc.Load().(string),
		QueueDrops: a.queueDrops.Load(), RejectedPkts: a.rejected.Load(), DecodeErrors: a.decodeErr.Load(),
		MissingTmpl: a.nf.Stats().MissingTemplate, DstsDropped: a.dstsDropped.Load(),
		SpreadPending: int(a.spreadPending.Load()), Exporters: []output.ExporterStatus{},
	}
	if a.ch != nil {
		le, _ := a.ch.LastError.Load().(string)
		st.ClickHouse = map[string]any{"inserted": a.ch.Inserted.Load(), "dropped": a.ch.Dropped.Load(),
			"pending": a.ch.Pending(), "errors": a.ch.Errors.Load(), "last_ok": a.ch.LastOK.Load(), "last_error": le}
	}
	a.expMu.Lock()
	for k, s := range a.exporters {
		kind, _ := s.kind.Load().(string)
		rate, src := s.lastRate.Load(), "exporter"
		if s.override > 0 {
			rate, src = s.override, "override"
		} else if rate == 0 {
			src = "unknown"
		}
		st.Exporters = append(st.Exporters, output.ExporterStatus{Address: k.addr.String(), Name: s.name, Kind: kind,
			Packets: s.packets.Load(), Records: s.records.Load(), LastSeen: s.lastSeen.Load(),
			SamplingRate: rate, SamplingFrom: src})
	}
	a.expMu.Unlock()
	return st
}

func (a *app) serveMetrics() {
	mux := http.NewServeMux()
	mux.Handle("/metrics", a.reg)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a.status())
	})
	srv := &http.Server{Addr: a.cfg.MetricsListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		a.log.Error("metrics listener", "err", err)
	}
}
