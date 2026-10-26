package agg

import (
	"net/netip"
	"sort"
	"time"
)

// Per-attack source tracking.
//
// For every protected destination the aggregator also keeps, per window (default 10 s), the
// traffic each source address sent it. At the end of the window the busiest sources of every
// destination above a rate threshold are returned for storage, so attack history can show who
// sent the traffic and from which networks. Memory is bounded per destination and in total;
// sources beyond the bounds are counted in the destination's total but not individually.

const (
	DefaultSourcesPerDst = 2048
	DefaultSourcesTotal  = 1_000_000
)

type srcStat struct {
	packets, bytes float64
	srcAS          uint32
	// Protocol and ports of this source's largest record: what it mostly sends.
	proto            uint8
	srcPort, dstPort uint16
	bestRecord       float64
	net              asnKey
	netSet           bool
}

type dstSources struct {
	prefix  netip.Prefix
	total   float64 // packets, every source (also those not tracked individually)
	bytes   float64
	srcs    map[netip.Addr]*srcStat
	dropped float64 // packets from sources not tracked because a bound was hit
	nets    map[asnKey]*netStat
}

type asnKey struct {
	asn uint32
	cc  string
}

type netStat struct {
	packets, bytes float64
	sources        int // distinct sources tracked individually (a lower bound when the bound was hit)
}

// NetRow is one source network (origin AS) of one destination over one window. Unlike SourceRow
// it covers every packet, including sources beyond the per-destination bound.
type NetRow struct {
	WindowStart time.Time
	Dst         netip.Addr
	Prefix      netip.Prefix
	ASN         uint32 // asndb.Unknown / asndb.Other are special
	Country     string
	PPS, BPS    float64
	Sources     int
	DstPPS      float64
}

// MaxNetsPerDst bounds the networks stored per destination per window; the rest are summed in
// one row with ASN = Other.
const MaxNetsPerDst = 100

// SourceRow is one source of one destination over one window (rates averaged over the window).
type SourceRow struct {
	WindowStart time.Time
	Dst         netip.Addr
	Prefix      netip.Prefix
	Src         netip.Addr
	SrcAS       uint32 // from the exporter; 0 if it did not send one
	PPS, BPS    float64
	Proto       uint8
	SrcPort     uint16
	DstPort     uint16
	DstPPS      float64 // the destination's total rate in the window, for shares
	Sources     int     // distinct sources tracked for this destination in the window
	Untracked   float64 // pps from sources beyond the memory bound
}

type sourceTracker struct {
	perDst, total int
	entries       int
	start         time.Time
	dsts          map[netip.Addr]*dstSources
	lookup        func(netip.Addr) (uint32, string) // origin AS and country; nil = unknown
	unknownASN    uint32
	otherASN      uint32
	nets          []NetRow // filled by flush
}

func newSourceTracker(cfg Config) *sourceTracker {
	perDst, total := cfg.SourcesPerDst, cfg.SourcesTotal
	if perDst <= 0 {
		perDst = DefaultSourcesPerDst
	}
	if total <= 0 {
		total = DefaultSourcesTotal
	}
	unknown, other := cfg.UnknownASN, cfg.OtherASN
	if unknown == 0 {
		unknown = 4294967294
	}
	if other == 0 {
		other = 4294967295
	}
	return &sourceTracker{perDst: perDst, total: total, dsts: map[netip.Addr]*dstSources{}, lookup: cfg.ASNLookup,
		unknownASN: unknown, otherASN: other}
}

func (t *sourceTracker) add(dst netip.Addr, p netip.Prefix, src netip.Addr, srcAS uint32, c *Counters, proto uint8, sport, dport uint16) {
	if t.start.IsZero() {
		t.start = time.Now()
	}
	d := t.dsts[dst]
	if d == nil {
		d = &dstSources{prefix: p, srcs: map[netip.Addr]*srcStat{}, nets: map[asnKey]*netStat{}}
		t.dsts[dst] = d
	}
	d.total += c.Packets
	d.bytes += c.Bytes
	s := d.srcs[src]
	isNew := false
	if s == nil {
		if len(d.srcs) < t.perDst && t.entries < t.total {
			s = &srcStat{}
			d.srcs[src] = s
			t.entries++
			isNew = true
		}
	}
	// Network totals cover every packet, tracked source or not.
	var k asnKey
	switch {
	case srcAS != 0:
		k.asn = srcAS
		if t.lookup != nil {
			if a, cc := t.lookup(src); a == srcAS {
				k.cc = cc
			}
		}
	case s != nil && !isNew && s.netSet:
		k = s.net
	case t.lookup != nil:
		k.asn, k.cc = t.lookup(src)
	default:
		k.asn = t.unknownASN
	}
	n := d.nets[k]
	if n == nil {
		n = &netStat{}
		d.nets[k] = n
	}
	n.packets += c.Packets
	n.bytes += c.Bytes
	if s == nil {
		d.dropped += c.Packets
		return
	}
	if isNew {
		n.sources++
		s.net, s.netSet = k, true
	}
	s.packets += c.Packets
	s.bytes += c.Bytes
	if srcAS != 0 {
		s.srcAS = srcAS
	}
	if c.Packets >= s.bestRecord {
		s.bestRecord, s.proto, s.srcPort, s.dstPort = c.Packets, proto, sport, dport
	}
}

// flush closes the window ending at `end`, returning the top `topN` sources of every destination
// whose average rate over the window reached minPPS (or that `hot` reports, e.g. inside an open
// incident, at any rate), and starts a new window.
func (t *sourceTracker) flush(end time.Time, minPPS float64, topN int, hot func(netip.Addr) bool) []SourceRow {
	start := t.start
	if start.IsZero() || !end.After(start) {
		start = end.Add(-10 * time.Second)
	}
	secs := end.Sub(start).Seconds()
	var out []SourceRow
	t.nets = t.nets[:0]
	for dst, d := range t.dsts {
		dpps := d.total / secs
		if len(d.srcs) == 0 || (dpps < minPPS && (hot == nil || !hot(dst))) {
			continue
		}
		keys := make([]asnKey, 0, len(d.nets))
		for k := range d.nets {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			pi, pj := d.nets[keys[i]].packets, d.nets[keys[j]].packets
			if pi != pj {
				return pi > pj
			}
			return keys[i].asn < keys[j].asn
		})
		var other netStat
		for i, k := range keys {
			n := d.nets[k]
			if i >= MaxNetsPerDst {
				other.packets += n.packets
				other.bytes += n.bytes
				other.sources += n.sources
				continue
			}
			t.nets = append(t.nets, NetRow{WindowStart: start, Dst: dst, Prefix: d.prefix, ASN: k.asn, Country: k.cc,
				PPS: n.packets / secs, BPS: n.bytes * 8 / secs, Sources: n.sources, DstPPS: dpps})
		}
		if other.packets > 0 {
			t.nets = append(t.nets, NetRow{WindowStart: start, Dst: dst, Prefix: d.prefix, ASN: t.otherASN,
				PPS: other.packets / secs, BPS: other.bytes * 8 / secs, Sources: other.sources, DstPPS: dpps})
		}
		list := make([]netip.Addr, 0, len(d.srcs))
		for a := range d.srcs {
			list = append(list, a)
		}
		sort.Slice(list, func(i, j int) bool {
			pi, pj := d.srcs[list[i]].packets, d.srcs[list[j]].packets
			if pi != pj {
				return pi > pj
			}
			return list[i].Less(list[j])
		})
		if len(list) > topN {
			list = list[:topN]
		}
		for _, a := range list {
			s := d.srcs[a]
			out = append(out, SourceRow{WindowStart: start, Dst: dst, Prefix: d.prefix, Src: a, SrcAS: s.srcAS,
				PPS: s.packets / secs, BPS: s.bytes * 8 / secs, Proto: s.proto, SrcPort: s.srcPort, DstPort: s.dstPort,
				DstPPS: dpps, Sources: len(d.srcs), Untracked: d.dropped / secs})
		}
	}
	t.dsts = map[netip.Addr]*dstSources{}
	t.entries = 0
	t.start = end
	return out
}
