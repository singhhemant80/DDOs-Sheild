package agg

import (
	"math"
	"net/netip"
	"testing"
	"time"

	"shield/collector/internal/flow"
	"shield/collector/internal/prefix"
)

func holder(ps ...string) *prefix.Holder {
	var l []netip.Prefix
	for _, p := range ps {
		l = append(l, netip.MustParsePrefix(p))
	}
	h := &prefix.Holder{}
	h.Store(prefix.New(l))
	return h
}

var (
	victim = netip.MustParseAddr("163.5.191.20")
	other  = netip.MustParseAddr("77.107.95.9")
	ts     = time.Unix(1_800_000_000, 0)
)

func rec(src string, dst netip.Addr, proto uint8, pkts, bytes uint64, rate uint32) *flow.Record {
	return &flow.Record{Src: netip.MustParseAddr(src), Dst: dst, Proto: proto, Packets: pkts, Bytes: bytes, SamplingRate: rate}
}

func TestScalingDirectionAndProvenance(t *testing.T) {
	a := New(Config{}, holder("163.5.191.0/24", "77.107.95.0/24"))
	a.Add(rec("198.51.100.1", victim, 17, 10, 15000, 1000))                     // in, sampled
	a.Add(rec("163.5.191.20", netip.MustParseAddr("8.8.8.8"), 6, 3, 300, 1000)) // out
	a.Add(rec("8.8.4.4", netip.MustParseAddr("8.8.8.8"), 6, 1, 1, 1))           // unrelated transit
	a.Add(rec("198.51.100.2", other, 6, 5, 500, 0))                             // in, unknown rate
	s := a.Tick(ts)
	if s.In.Packets != 10_000+5 || s.Out.Packets != 3000 || s.Unmatched.Packets != 1 {
		t.Fatalf("in=%v out=%v unmatched=%v", s.In.Packets, s.Out.Packets, s.Unmatched.Packets)
	}
	if s.InProv != "estimated" {
		t.Fatalf("mixed known/unknown sampling must be estimated, got %s", s.InProv)
	}
	if len(s.Dsts) != 2 || s.Dsts[0].IP != victim || s.Dsts[0].Provenance != "sampled" ||
		s.Dsts[1].Provenance != "estimated" || s.Dsts[0].Prefix.String() != "163.5.191.0/24" {
		t.Fatalf("dsts %+v", s.Dsts)
	}
	if s.Dsts[0].C.Bytes != 15_000_000 || s.Dsts[0].C.UDP != 10_000 {
		t.Fatalf("victim counters %+v", s.Dsts[0].C)
	}
}

func TestTCPFlagClassesAndReflection(t *testing.T) {
	a := New(Config{}, holder("163.5.191.0/24"))
	syn := rec("198.51.100.1", victim, 6, 100, 6000, 1)
	syn.TCPFlags = flow.TCPSyn
	synack := rec("198.51.100.1", victim, 6, 7, 420, 1)
	synack.TCPFlags = flow.TCPSyn | flow.TCPAck
	ack := rec("198.51.100.1", victim, 6, 9, 540, 1)
	ack.TCPFlags = flow.TCPAck
	ntp := rec("198.51.100.5", victim, 17, 50, 24000, 1)
	ntp.SrcPort = 123
	frag := rec("198.51.100.6", victim, 17, 4, 6000, 1)
	frag.Fragment = true
	for _, r := range []*flow.Record{syn, synack, ack, ntp, frag} {
		a.Add(r)
	}
	c := a.Tick(ts).Dsts[0].C
	if c.SYN != 100 || c.ACKOnly != 9 || c.Fragments != 4 || c.Reflect[1] != 50 || c.TCP != 116 {
		t.Fatalf("%+v", c)
	}
}

func TestLongFlowsAreSpreadNotSpiked(t *testing.T) {
	a := New(Config{}, holder("163.5.191.0/24"))
	r := rec("198.51.100.1", victim, 6, 60_000, 60_000_000, 1)
	r.DurationMs = 60_000
	a.Add(r)
	total := 0.0
	for i := 0; i < 60; i++ {
		s := a.Tick(ts.Add(time.Duration(i) * time.Second))
		if len(s.Dsts) != 1 || math.Abs(s.Dsts[0].C.Packets-1000) > 1e-6 {
			t.Fatalf("second %d: %+v", i, s.Dsts)
		}
		total += s.In.Packets
	}
	if math.Abs(total-60_000) > 1e-3 {
		t.Fatalf("total %v must be preserved", total)
	}
	if s := a.Tick(ts.Add(61 * time.Second)); len(s.Dsts) != 0 || len(a.dsts) != 0 {
		t.Fatalf("state must be released after spreading, %d left", len(a.dsts))
	}
}

func TestDistinctSourceEstimate(t *testing.T) {
	a := New(Config{}, holder("163.5.191.0/24"))
	for i := 0; i < 3000; i++ {
		ip := netip.AddrFrom4([4]byte{198, byte(i >> 16), byte(i >> 8), byte(i)})
		a.Add(&flow.Record{Src: ip, Dst: victim, Proto: 17, Packets: 1, Bytes: 100, SamplingRate: 1})
	}
	est := a.Tick(ts).Dsts[0].Sources
	if est < 2700 || est > 3300 {
		t.Fatalf("estimate %v not within 10%% of 3000", est)
	}
}

func TestMaxDstsBound(t *testing.T) {
	a := New(Config{MaxDsts: 10}, holder("163.5.191.0/24"))
	for i := 0; i < 50; i++ {
		a.Add(rec("198.51.100.1", netip.AddrFrom4([4]byte{163, 5, 191, byte(i)}), 17, 1, 1, 1))
	}
	s := a.Tick(ts)
	if len(s.Dsts) != 10 || a.Dropped != 40 || s.In.Packets != 50 {
		t.Fatalf("dsts=%d dropped=%d in=%v", len(s.Dsts), a.Dropped, s.In.Packets)
	}
}

func TestPrefixMostSpecific(t *testing.T) {
	h := holder("163.52.252.0/23", "163.52.253.128/25", "2a0f::/32")
	p, ok := h.Load().Lookup(netip.MustParseAddr("163.52.253.200"))
	if !ok || p.String() != "163.52.253.128/25" {
		t.Fatal(p)
	}
	if _, ok := h.Load().Lookup(netip.MustParseAddr("163.52.254.1")); ok {
		t.Fatal("outside")
	}
	if p, ok := h.Load().Lookup(netip.MustParseAddr("2a0f::5")); !ok || p.Bits() != 32 {
		t.Fatal("v6")
	}
}
