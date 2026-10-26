// Package output defines the JSON contract between the collector and its consumers
// (API, dashboard, detector) plus the ClickHouse row shapes.
package output

import (
	"strconv"
	"time"

	"shield/collector/internal/agg"
)

// Redis keys and channels. Keep in sync with backend/app/traffic.py.
const (
	KeyPrefixes  = "shield:config:prefixes"  // written by the API: {"prefixes":["163.5.191.0/24",...],"version":N}
	ChanTraffic  = "shield:traffic"          // PUBLISH compact Snapshot every second
	KeyLatest    = "shield:traffic:latest"   // last compact Snapshot (EX 15)
	KeyHistory   = "shield:traffic:history"  // LPUSH compact history points, capped
	StreamFull   = "shield:traffic:stream"   // XADD full per-destination detail for the detector
	KeyIfaces    = "shield:ifaces"           // HASH "agent|ifIndex" -> iftrack.Rate JSON
	KeyCollector = "shield:collector:status" // Status JSON (EX 15)
	KeyHot       = "shield:detector:hot"     // written by the detector: {"targets":["163.5.191.30/32",...]} (EX 30)
	HistoryLen   = 3600
)

type Rates struct {
	PPS        float64 `json:"pps"`
	BPS        float64 `json:"bps"`
	TCPPPS     float64 `json:"tcp_pps"`
	UDPPPS     float64 `json:"udp_pps"`
	ICMPPPS    float64 `json:"icmp_pps"`
	OtherPPS   float64 `json:"other_pps"`
	Provenance string  `json:"provenance"`
}

type Dst struct {
	IP          string             `json:"ip"`
	Prefix      string             `json:"prefix"`
	PPS         float64            `json:"pps"`
	BPS         float64            `json:"bps"`
	FlowRecords float64            `json:"flow_records"`
	TCPPPS      float64            `json:"tcp_pps"`
	UDPPPS      float64            `json:"udp_pps"`
	ICMPPPS     float64            `json:"icmp_pps"`
	OtherPPS    float64            `json:"other_pps"`
	SYNPPS      float64            `json:"syn_pps"`
	ACKPPS      float64            `json:"ack_pps"`
	RSTPPS      float64            `json:"rst_pps"`
	FragPPS     float64            `json:"frag_pps"`
	Reflect     map[string]float64 `json:"reflect,omitempty"` // UDP source port -> pps
	Sources     float64            `json:"sources_est"`
	Provenance  string             `json:"provenance"`
}

type Snapshot struct {
	TS       int64 `json:"ts"`
	In       Rates `json:"in"`
	Out      Rates `json:"out"`
	Dsts     []Dst `json:"dsts"`
	DstCount int   `json:"dst_count"` // total active protected destinations this second
}

// HistoryPoint is the compact form kept for charts (one per second).
type HistoryPoint struct {
	TS     int64   `json:"ts"`
	InPPS  float64 `json:"in_pps"`
	InBPS  float64 `json:"in_bps"`
	OutPPS float64 `json:"out_pps"`
	OutBPS float64 `json:"out_bps"`
	TCP    float64 `json:"tcp_pps"`
	UDP    float64 `json:"udp_pps"`
	ICMP   float64 `json:"icmp_pps"`
	Other  float64 `json:"other_pps"`
	Prov   string  `json:"provenance"`
}

func rates(c *agg.Counters, prov string) Rates {
	return Rates{PPS: c.Packets, BPS: c.Bytes * 8, TCPPPS: c.TCP, UDPPPS: c.UDP, ICMPPPS: c.ICMP,
		OtherPPS: c.Other, Provenance: prov}
}

func dst(d *agg.Dst) Dst {
	o := Dst{IP: d.IP.String(), Prefix: d.Prefix.String(), PPS: d.C.Packets, BPS: d.C.Bytes * 8,
		FlowRecords: d.C.FlowRecords, TCPPPS: d.C.TCP, UDPPPS: d.C.UDP, ICMPPPS: d.C.ICMP,
		OtherPPS: d.C.Other, SYNPPS: d.C.SYN, ACKPPS: d.C.ACKOnly, RSTPPS: d.C.RST,
		FragPPS: d.C.Fragments, Sources: d.Sources, Provenance: d.Provenance}
	for i, v := range d.C.Reflect {
		if v > 0 {
			if o.Reflect == nil {
				o.Reflect = map[string]float64{}
			}
			o.Reflect[strconv.Itoa(int(agg.ReflectPorts[i]))] = v
		}
	}
	return o
}

// Build returns the compact snapshot (top N destinations) and the full one (filtered by minPPS, capped).
func Build(s *agg.Second, top, fullMax int, minPPS float64) (compact, full Snapshot, hist HistoryPoint) {
	in, out := rates(&s.In, s.InProv), rates(&s.Out, s.OutProv)
	compact = Snapshot{TS: s.TS.Unix(), In: in, Out: out, DstCount: len(s.Dsts)}
	full = compact
	for i := range s.Dsts {
		d := dst(&s.Dsts[i])
		if i < top {
			compact.Dsts = append(compact.Dsts, d)
		}
		if len(full.Dsts) < fullMax && d.PPS >= minPPS {
			full.Dsts = append(full.Dsts, d)
		}
	}
	if compact.Dsts == nil {
		compact.Dsts = []Dst{}
	}
	if full.Dsts == nil {
		full.Dsts = []Dst{}
	}
	hist = HistoryPoint{TS: compact.TS, InPPS: in.PPS, InBPS: in.BPS, OutPPS: out.PPS, OutBPS: out.BPS,
		TCP: in.TCPPPS, UDP: in.UDPPPS, ICMP: in.ICMPPPS, Other: in.OtherPPS, Prov: in.Provenance}
	return
}

// ---------------------------------------------------------------- ClickHouse rows

func chTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") }

type DstRow struct {
	TS         string             `json:"ts"`
	Dst        string             `json:"dst"`
	Prefix     string             `json:"prefix"`
	PPS        float64            `json:"pps"`
	BPS        float64            `json:"bps"`
	FlowRecs   float64            `json:"flow_records"`
	TCP        float64            `json:"tcp_pps"`
	UDP        float64            `json:"udp_pps"`
	ICMP       float64            `json:"icmp_pps"`
	Other      float64            `json:"other_pps"`
	SYN        float64            `json:"syn_pps"`
	ACK        float64            `json:"ack_pps"`
	RST        float64            `json:"rst_pps"`
	Frag       float64            `json:"frag_pps"`
	Reflect    map[string]float64 `json:"reflect"`
	Sources    float64            `json:"sources_est"`
	Provenance string             `json:"provenance"`
}

func DstRowOf(ts time.Time, d Dst) DstRow {
	r := DstRow{TS: chTime(ts), Dst: d.IP, Prefix: d.Prefix, PPS: d.PPS, BPS: d.BPS, FlowRecs: d.FlowRecords,
		TCP: d.TCPPPS, UDP: d.UDPPPS, ICMP: d.ICMPPPS, Other: d.OtherPPS, SYN: d.SYNPPS, ACK: d.ACKPPS,
		RST: d.RSTPPS, Frag: d.FragPPS, Reflect: d.Reflect, Sources: d.Sources, Provenance: d.Provenance}
	if r.Reflect == nil {
		r.Reflect = map[string]float64{}
	}
	return r
}

// SrcRow is one row of shield.src_10s: one source of one destination over one window.
type SrcRow struct {
	TS        string  `json:"ts"`
	Dst       string  `json:"dst"`
	Prefix    string  `json:"prefix"`
	Src       string  `json:"src"`
	SrcAS     uint32  `json:"src_as"`
	PPS       float64 `json:"pps"`
	BPS       float64 `json:"bps"`
	Proto     uint8   `json:"proto"`
	SrcPort   uint16  `json:"src_port"`
	DstPort   uint16  `json:"dst_port"`
	DstPPS    float64 `json:"dst_pps"`
	Sources   uint32  `json:"sources"`
	Untracked float64 `json:"untracked_pps"`
}

func SrcRowOf(r agg.SourceRow) SrcRow {
	return SrcRow{TS: chTime(r.WindowStart), Dst: r.Dst.String(), Prefix: r.Prefix.String(), Src: r.Src.String(),
		SrcAS: r.SrcAS, PPS: r.PPS, BPS: r.BPS, Proto: r.Proto, SrcPort: r.SrcPort, DstPort: r.DstPort,
		DstPPS: r.DstPPS, Sources: uint32(r.Sources), Untracked: r.Untracked}
}

// NetRow is one row of shield.asn_10s: one source network (origin AS) of one destination.
type NetRow struct {
	TS      string  `json:"ts"`
	Dst     string  `json:"dst"`
	Prefix  string  `json:"prefix"`
	ASN     uint32  `json:"asn"`
	Country string  `json:"country"`
	PPS     float64 `json:"pps"`
	BPS     float64 `json:"bps"`
	Sources uint32  `json:"sources"`
	DstPPS  float64 `json:"dst_pps"`
}

func NetRowOf(r agg.NetRow) NetRow {
	return NetRow{TS: chTime(r.WindowStart), Dst: r.Dst.String(), Prefix: r.Prefix.String(), ASN: r.ASN,
		Country: r.Country, PPS: r.PPS, BPS: r.BPS, Sources: uint32(r.Sources), DstPPS: r.DstPPS}
}

type TotalsRow struct {
	TS         string  `json:"ts"`
	Direction  string  `json:"direction"`
	PPS        float64 `json:"pps"`
	BPS        float64 `json:"bps"`
	TCP        float64 `json:"tcp_pps"`
	UDP        float64 `json:"udp_pps"`
	ICMP       float64 `json:"icmp_pps"`
	Other      float64 `json:"other_pps"`
	Provenance string  `json:"provenance"`
}

func TotalsRowOf(ts time.Time, dir string, r Rates) TotalsRow {
	return TotalsRow{TS: chTime(ts), Direction: dir, PPS: r.PPS, BPS: r.BPS, TCP: r.TCPPPS, UDP: r.UDPPPS,
		ICMP: r.ICMPPPS, Other: r.OtherPPS, Provenance: r.Provenance}
}

type IfaceRow struct {
	TS      string  `json:"ts"`
	Agent   string  `json:"agent"`
	IfIndex uint32  `json:"if_index"`
	IfName  string  `json:"if_name"`
	InBPS   float64 `json:"in_bps"`
	OutBPS  float64 `json:"out_bps"`
	InPPS   float64 `json:"in_pps"`
	OutPPS  float64 `json:"out_pps"`
	Speed   uint64  `json:"speed_bps"`
	Source  string  `json:"source"`
}

type RawRow struct {
	TS       string `json:"ts"`
	Kind     string `json:"kind"`
	Exporter string `json:"exporter"`
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Proto    uint8  `json:"proto"`
	SrcPort  uint16 `json:"src_port"`
	DstPort  uint16 `json:"dst_port"`
	Flags    uint8  `json:"tcp_flags"`
	Bytes    uint64 `json:"bytes"`
	Packets  uint64 `json:"packets"`
	Sampling uint32 `json:"sampling_rate"`
	Duration uint32 `json:"duration_ms"`
}

// Status is the collector health document.
type Status struct {
	TS            int64            `json:"ts"`
	Version       string           `json:"version"`
	StartedAt     int64            `json:"started_at"`
	Prefixes      int              `json:"prefixes"`
	PrefixSource  string           `json:"prefix_source"`
	Exporters     []ExporterStatus `json:"exporters"`
	QueueDrops    uint64           `json:"queue_drops"`
	RejectedPkts  uint64           `json:"rejected_packets"`
	DecodeErrors  uint64           `json:"decode_errors"`
	MissingTmpl   uint64           `json:"missing_template_records"`
	DstsDropped   uint64           `json:"destinations_dropped"`
	ClickHouse    map[string]any   `json:"clickhouse"`
	SpreadPending int              `json:"spread_pending"`
}

type ExporterStatus struct {
	Address      string `json:"address"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	Packets      uint64 `json:"packets"`
	Records      uint64 `json:"records"`
	LastSeen     int64  `json:"last_seen"`
	SamplingRate uint32 `json:"sampling_rate"`
	SamplingFrom string `json:"sampling_source"` // exporter | override | unknown
}
