// Package agg turns flow records into per-second, per-destination traffic statistics.
//
// Time model
//   - Records are bucketed by the second they ARRIVE in.
//   - A flow whose duration exceeds SpreadThreshold is spread evenly over the following
//     min(duration, MaxSpread) seconds instead of being counted as one spike. This keeps
//     long-lived flows (exported once per active timeout) from appearing as bursts, at the
//     cost of showing their traffic up to MaxSpread seconds late. Short flows - which is
//     what floods consist of - are counted immediately.
//   - For timely detection configure exporters with a short active timeout (see docs).
//
// Scaling and provenance
//   - Packets/bytes are multiplied by the record's sampling rate.
//   - A destination's figures are "sampled" when every contributing record had a known
//     rate, otherwise "estimated" (unknown rate treated as 1:1).
package agg

import (
	"math"
	"math/bits"
	"net/netip"
	"sort"
	"time"

	"shield/collector/internal/flow"
	"shield/collector/internal/prefix"
)

// Reflection source ports tracked for amplification detection (Phase 4).
var ReflectPorts = [...]uint16{53, 123, 1900, 389, 11211, 19, 161, 3702, 5683, 3283, 111, 137}

type Counters struct {
	Packets, Bytes                float64
	FlowRecords                   float64
	TCP, UDP, ICMP, Other         float64 // packets by protocol
	TCPBytes, UDPBytes, ICMPBytes float64
	SYN, ACKOnly, RST             float64 // TCP packets whose flow flags match
	Fragments                     float64
	Reflect                       [len(ReflectPorts)]float64 // UDP packets from reflection src ports
	unknownSampling               bool
	sources                       lcounter
}

func (c *Counters) add(o *Counters, f float64) {
	c.Packets += o.Packets * f
	c.Bytes += o.Bytes * f
	c.FlowRecords += o.FlowRecords * f
	c.TCP += o.TCP * f
	c.UDP += o.UDP * f
	c.ICMP += o.ICMP * f
	c.Other += o.Other * f
	c.TCPBytes += o.TCPBytes * f
	c.UDPBytes += o.UDPBytes * f
	c.ICMPBytes += o.ICMPBytes * f
	c.SYN += o.SYN * f
	c.ACKOnly += o.ACKOnly * f
	c.RST += o.RST * f
	c.Fragments += o.Fragments * f
	for i := range c.Reflect {
		c.Reflect[i] += o.Reflect[i] * f
	}
	c.unknownSampling = c.unknownSampling || o.unknownSampling
}

func fromRecord(r *flow.Record) Counters {
	rate := float64(r.SamplingRate)
	var c Counters
	if rate == 0 {
		rate = 1
		c.unknownSampling = true
	}
	p, b := float64(r.Packets)*rate, float64(r.Bytes)*rate
	c.Packets, c.Bytes, c.FlowRecords = p, b, 1
	switch r.Proto {
	case 6:
		c.TCP, c.TCPBytes = p, b
		switch {
		case r.TCPFlags&(flow.TCPSyn|flow.TCPAck) == flow.TCPSyn:
			c.SYN = p
		case r.TCPFlags&flow.TCPRst != 0:
			c.RST = p
		case r.TCPFlags&(flow.TCPSyn|flow.TCPFin|flow.TCPRst|flow.TCPPsh) == 0 && r.TCPFlags&flow.TCPAck != 0:
			c.ACKOnly = p
		}
	case 17:
		c.UDP, c.UDPBytes = p, b
		for i, port := range ReflectPorts {
			if r.SrcPort == port {
				c.Reflect[i] = p
				break
			}
		}
	case 1, 58:
		c.ICMP, c.ICMPBytes = p, b
	default:
		c.Other = p
	}
	if r.Fragment {
		c.Fragments = p
	}
	return c
}

// lcounter is a linear-counting distinct estimator (4096 bits = 512 bytes, accurate to ~20k).
type lcounter struct{ bits *[64]uint64 }

func (l *lcounter) add(a netip.Addr) {
	if l.bits == nil {
		l.bits = new([64]uint64)
	}
	h := hashAddr(a) & 4095
	l.bits[h>>6] |= 1 << (h & 63)
}

func (l *lcounter) estimate() float64 {
	if l.bits == nil {
		return 0
	}
	set := 0
	for _, w := range l.bits {
		set += bits.OnesCount64(w)
	}
	const m = 4096.0
	if set >= 4096 {
		return m * math.Log(m) // saturated: report the ceiling
	}
	return math.Round(-m * math.Log((m-float64(set))/m))
}

func hashAddr(a netip.Addr) uint64 {
	b := a.As16()
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h ^ h>>29
}

type spread struct {
	perSec Counters
	left   int
}

type dstState struct {
	prefix  netip.Prefix
	cur     Counters
	spreads []spread
}

// Dst is one destination's statistics for one second (rates per second).
type Dst struct {
	IP         netip.Addr
	Prefix     netip.Prefix
	C          Counters
	Sources    float64
	Provenance string
}

// Second is everything observed in one closed one-second bucket.
type Second struct {
	TS                 time.Time
	In, Out, Unmatched Counters
	InProv, OutProv    string
	Dsts               []Dst // protected destinations, sorted by packets desc
	SpreadPending      int
}

type Config struct {
	SpreadThreshold time.Duration
	MaxSpread       time.Duration
	MaxDsts         int // memory bound on tracked destinations
}

type Aggregator struct {
	cfg      Config
	prefixes *prefix.Holder
	dsts     map[netip.Addr]*dstState
	in, out  Counters
	unmatch  Counters
	Dropped  uint64 // destinations not tracked because MaxDsts was hit
}

func New(cfg Config, prefixes *prefix.Holder) *Aggregator {
	if cfg.SpreadThreshold == 0 {
		cfg.SpreadThreshold = 2 * time.Second
	}
	if cfg.MaxSpread == 0 {
		cfg.MaxSpread = 120 * time.Second
	}
	if cfg.MaxDsts == 0 {
		cfg.MaxDsts = 200_000
	}
	return &Aggregator{cfg: cfg, prefixes: prefixes, dsts: map[netip.Addr]*dstState{}}
}

// Add accounts one record. Not safe for concurrent use: call from the aggregator goroutine.
func (a *Aggregator) Add(r *flow.Record) {
	ps := a.prefixes.Load()
	c := fromRecord(r)
	if p, ok := ps.Lookup(r.Dst); ok {
		st := a.dsts[r.Dst]
		if st == nil {
			if len(a.dsts) >= a.cfg.MaxDsts {
				a.Dropped++
				a.in.add(&c, 1)
				return
			}
			st = &dstState{prefix: p}
			a.dsts[r.Dst] = st
		}
		st.cur.sources.add(r.Src)
		dur := time.Duration(r.DurationMs) * time.Millisecond
		if dur > a.cfg.SpreadThreshold {
			n := int(min(dur, a.cfg.MaxSpread) / time.Second)
			var per Counters
			per.add(&c, 1/float64(n))
			// The first second's share is counted now; the rest in following ticks.
			st.cur.add(&per, 1)
			if n > 1 {
				st.spreads = append(st.spreads, spread{perSec: per, left: n - 1})
			}
			a.in.add(&per, 1)
			a.in.FlowRecords += 1 - per.FlowRecords // count the record once, now
			st.cur.FlowRecords += 1 - per.FlowRecords
			return
		}
		st.cur.add(&c, 1)
		a.in.add(&c, 1)
		return
	}
	if _, ok := ps.Lookup(r.Src); ok {
		a.out.add(&c, 1)
		return
	}
	a.unmatch.add(&c, 1)
}

// Tick closes the current second and returns its statistics.
func (a *Aggregator) Tick(ts time.Time) Second {
	s := Second{TS: ts, In: a.in, Out: a.out, Unmatched: a.unmatch}
	s.InProv, s.OutProv = prov(&a.in), prov(&a.out)
	a.in, a.out, a.unmatch = Counters{}, Counters{}, Counters{}
	s.Dsts = make([]Dst, 0, len(a.dsts))
	for ip, st := range a.dsts {
		if st.cur.Packets > 0 {
			s.Dsts = append(s.Dsts, Dst{IP: ip, Prefix: st.prefix, C: st.cur,
				Sources: st.cur.sources.estimate(), Provenance: prov(&st.cur)})
		}
		// Next second starts with the spread contributions of long flows.
		st.cur = Counters{}
		kept := st.spreads[:0]
		for _, sp := range st.spreads {
			st.cur.add(&sp.perSec, 1)
			a.in.add(&sp.perSec, 1)
			sp.left--
			if sp.left > 0 {
				kept = append(kept, sp)
			}
		}
		st.cur.FlowRecords = 0
		st.spreads = kept
		s.SpreadPending += len(kept)
		if st.cur.Packets == 0 && len(kept) == 0 {
			delete(a.dsts, ip) // idle destinations cost nothing
		}
	}
	a.in.FlowRecords = 0
	sort.Slice(s.Dsts, func(i, j int) bool { return s.Dsts[i].C.Packets > s.Dsts[j].C.Packets })
	return s
}

func prov(c *Counters) string {
	switch {
	case c.Packets == 0:
		return "unavailable"
	case c.unknownSampling:
		return "estimated"
	default:
		return "sampled"
	}
}
