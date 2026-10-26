// shield-flowgen sends SYNTHETIC flow-export packets (NetFlow v9 / IPFIX / sFlow) describing
// lab traffic scenarios to a collector. It never generates attack traffic: it only emits the
// metadata a router would export. By default it refuses collectors outside loopback/private ranges.
//
//	shield-flowgen -collector 127.0.0.1:2055 -format netflow -scenario udp-flood -victim 163.5.191.20
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"time"

	"shield/collector/internal/encode"
)

type scenario struct {
	name     string
	baseline float64 // total baseline pps across the prefix
	attack   float64 // additional pps to the victim
	kind     string  // udp | syn | ack | reflection | icmp | frag | none
	sources  int     // distinct attack sources
	pktSize  int
}

var scenarios = map[string]scenario{
	"baseline":    {name: "baseline", baseline: 20_000, kind: "none"},
	"udp-flood":   {name: "udp-flood", baseline: 20_000, attack: 1_000_000, kind: "udp", sources: 5000, pktSize: 512},
	"syn-flood":   {name: "syn-flood", baseline: 20_000, attack: 800_000, kind: "syn", sources: 20000, pktSize: 60},
	"ack-flood":   {name: "ack-flood", baseline: 20_000, attack: 600_000, kind: "ack", sources: 8000, pktSize: 60},
	"ntp-reflect": {name: "ntp-reflect", baseline: 20_000, attack: 400_000, kind: "reflection", sources: 3000, pktSize: 468},
	"dns-reflect": {name: "dns-reflect", baseline: 20_000, attack: 300_000, kind: "dns", sources: 2500, pktSize: 1400},
	"icmp-flood":  {name: "icmp-flood", baseline: 20_000, attack: 300_000, kind: "icmp", sources: 2000, pktSize: 98},
	"frag-flood":  {name: "frag-flood", baseline: 20_000, attack: 200_000, kind: "frag", sources: 1000, pktSize: 1480},
	// A legitimate spike: many real clients, normal TCP mix, to exercise false-positive handling (Phase 4).
	"flash-crowd": {name: "flash-crowd", baseline: 20_000, attack: 150_000, kind: "web", sources: 15000, pktSize: 900},
}

func main() {
	collector := flag.String("collector", "127.0.0.1:2055", "collector host:port")
	format := flag.String("format", "netflow", "netflow | ipfix | sflow")
	scen := flag.String("scenario", "baseline", "scenario name (see -list)")
	list := flag.Bool("list", false, "list scenarios")
	prefixS := flag.String("prefix", "163.5.191.0/24", "protected prefix to simulate")
	victimS := flag.String("victim", "163.5.191.20", "destination under simulated attack")
	sampling := flag.Uint("sampling", 1024, "1-in-N sampling the simulated router applies")
	noRate := flag.Bool("no-sampling-info", false, "do not export the sampling rate (tests 'estimated' provenance)")
	duration := flag.Duration("duration", 30*time.Second, "how long to run")
	seed := flag.Int64("seed", 1, "random seed")
	allowPublic := flag.Bool("allow-public-collector", false, "allow a collector outside loopback/private ranges")
	agentS := flag.String("agent", "10.255.0.1", "sFlow agent address to claim")
	flag.Parse()

	if *list {
		for k, s := range scenarios {
			fmt.Printf("%-12s baseline %.0f pps, +%.0f pps %s to victim from %d sources\n", k, s.baseline, s.attack, s.kind, s.sources)
		}
		return
	}
	sc, ok := scenarios[*scen]
	if !ok {
		fail("unknown scenario %q (use -list)", *scen)
	}
	pfx := netip.MustParsePrefix(*prefixS)
	victim := netip.MustParseAddr(*victimS)
	if !pfx.Contains(victim) {
		fail("victim %s is not inside %s", victim, pfx)
	}
	ua, err := net.ResolveUDPAddr("udp", *collector)
	if err != nil {
		fail("%v", err)
	}
	ca, _ := netip.AddrFromSlice(ua.IP)
	ca = ca.Unmap()
	if !*allowPublic && !(ca.IsLoopback() || ca.IsPrivate()) {
		fail("collector %s is not loopback/private; pass -allow-public-collector if this is really your lab", ca)
	}
	conn, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		fail("%v", err)
	}
	defer conn.Close()

	rng := rand.New(rand.NewSource(*seed))
	rate := uint32(*sampling)
	exportRate := rate
	if *noRate {
		exportRate = 0
	}
	v9 := &encode.V9{SourceID: 1, SamplingRate: exportRate, WithTemplates: true}
	ipfix := &encode.IPFIX{Domain: 1, SamplingRate: exportRate, WithTemplates: true}
	sf := &encode.SFlow{Agent: netip.MustParseAddr(*agentS), SamplingRate: rate}
	var inOctets uint64

	fmt.Printf("scenario=%s format=%s sampling=1:%d victim=%s expected victim pps≈%.0f (baseline share excluded) total in≈%.0f pps\n",
		sc.name, *format, rate, victim, sc.attack, sc.baseline+sc.attack)
	start := time.Now()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	sent := 0
	for time.Since(start) < *duration {
		flows, wire := secondOfTraffic(rng, sc, pfx, victim, float64(rate), *format == "sflow")
		inOctets += wire
		now := time.Now()
		var pkts [][]byte
		switch *format {
		case "netflow":
			pkts = v9.Packets(flows, uint32(now.Unix()), uint32(time.Since(start).Milliseconds())+100_000)
		case "ipfix":
			pkts = ipfix.Packets(flows, uint32(now.Unix()), uint64(now.UnixMilli()))
		case "sflow":
			ctr := []encode.IfCounter{{IfIndex: 1, SpeedBps: 10_000_000_000, InOctets: inOctets}}
			pkts = sf.Packets(flows, ctr, uint32(time.Since(start).Milliseconds()))
		default:
			fail("unknown format %q", *format)
		}
		for _, p := range pkts {
			if _, err := conn.Write(p); err != nil {
				fmt.Fprintln(os.Stderr, "send:", err)
			}
			sent++
		}
		<-tick.C
	}
	fmt.Printf("done: %d export packets in %s\n", sent, time.Since(start).Round(time.Second))
}

// secondOfTraffic returns the flow records (already "sampled") a router would export for one
// second of the scenario, plus the unsampled wire octets (for interface counters).
func secondOfTraffic(rng *rand.Rand, sc scenario, pfx netip.Prefix, victim netip.Addr, rate float64, perPacket bool) ([]encode.Flow, uint64) {
	var flows []encode.Flow
	var wire uint64
	// Baseline: spread across up to 50 hosts in the prefix, normal protocol mix.
	hosts := hostsIn(pfx, 50)
	add := func(f encode.Flow, realPkts float64, size int) {
		wire += uint64(realPkts * float64(size))
		sampled := realPkts / rate
		n := int(sampled)
		if rng.Float64() < sampled-float64(n) {
			n++
		}
		if n == 0 {
			return
		}
		if perPacket {
			for i := 0; i < n; i++ {
				g := f
				g.Bytes = uint64(size)
				flows = append(flows, g)
			}
			return
		}
		f.Packets = uint64(n)
		f.Bytes = uint64(n * size)
		flows = append(flows, f)
	}
	perHost := sc.baseline / float64(len(hosts))
	for _, h := range hosts {
		src := randAddr(rng, 64, 1000)
		r := rng.Float64()
		switch {
		case r < 0.7:
			add(encode.Flow{Src: src, Dst: h, Proto: 6, SrcPort: uint16(1024 + rng.Intn(60000)), DstPort: 443,
				TCPFlags: 0x18 | 0x10, DurationMs: 1000}, perHost, 900)
		case r < 0.95:
			add(encode.Flow{Src: src, Dst: h, Proto: 17, SrcPort: uint16(1024 + rng.Intn(60000)), DstPort: 51820,
				DurationMs: 1000}, perHost, 400)
		default:
			add(encode.Flow{Src: src, Dst: h, Proto: 1, DurationMs: 1000}, perHost, 98)
		}
	}
	if sc.attack == 0 {
		return flows, wire
	}
	// Attack: split across a sample of sources so per-flow sampled counts stay realistic.
	srcs := min(sc.sources, 400)
	per := sc.attack / float64(srcs)
	for i := 0; i < srcs; i++ {
		src := randAddr(rng, 0, sc.sources)
		f := encode.Flow{Src: src, Dst: victim, DurationMs: 1000}
		switch sc.kind {
		case "udp":
			f.Proto, f.SrcPort, f.DstPort = 17, uint16(1024+rng.Intn(60000)), uint16(1+rng.Intn(65535))
		case "syn":
			f.Proto, f.SrcPort, f.DstPort, f.TCPFlags = 6, uint16(1024+rng.Intn(60000)), 80, 0x02
		case "ack":
			f.Proto, f.SrcPort, f.DstPort, f.TCPFlags = 6, uint16(1024+rng.Intn(60000)), 443, 0x10
		case "reflection":
			f.Proto, f.SrcPort, f.DstPort = 17, 123, uint16(1024+rng.Intn(60000))
		case "dns":
			f.Proto, f.SrcPort, f.DstPort = 17, 53, uint16(1024+rng.Intn(60000))
		case "icmp":
			f.Proto = 1
		case "frag":
			f.Proto, f.Fragment = 17, true
		case "web":
			f.Proto, f.SrcPort, f.DstPort, f.TCPFlags = 6, uint16(1024+rng.Intn(60000)), 443, 0x1b
		}
		add(f, per, sc.pktSize)
	}
	return flows, wire
}

func hostsIn(p netip.Prefix, n int) []netip.Addr {
	var out []netip.Addr
	a := p.Addr().Next()
	for len(out) < n && p.Contains(a) {
		out = append(out, a)
		a = a.Next()
	}
	return out
}

// randAddr returns documentation-range sources (198.18.0.0/15 benchmark space) so nothing
// resembles real Internet hosts.
func randAddr(rng *rand.Rand, offset, n int) netip.Addr {
	i := offset + rng.Intn(max(n, 1))
	return netip.AddrFrom4([4]byte{198, 18 + byte(i>>16&1), byte(i >> 8), byte(i)})
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "shield-flowgen: "+f+"\n", a...)
	os.Exit(2)
}
