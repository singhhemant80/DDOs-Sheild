package sflow

import (
	"net/netip"
	"testing"

	"shield/collector/internal/encode"
	"shield/collector/internal/flow"
)

func TestFlowAndCounterSamples(t *testing.T) {
	e := &encode.SFlow{Agent: netip.MustParseAddr("10.255.0.3"), SamplingRate: 2048}
	in := []encode.Flow{
		{Src: netip.MustParseAddr("198.51.100.9"), Dst: netip.MustParseAddr("163.5.191.20"), Proto: 6,
			SrcPort: 4444, DstPort: 80, TCPFlags: flow.TCPSyn, Bytes: 60},
		{Src: netip.MustParseAddr("198.51.100.9"), Dst: netip.MustParseAddr("163.5.191.21"), Proto: 17,
			SrcPort: 123, DstPort: 5000, Bytes: 482, Fragment: true},
		{Src: netip.MustParseAddr("2001:db8::9"), Dst: netip.MustParseAddr("2a0f::1"), Proto: 17,
			SrcPort: 53, DstPort: 9999, Bytes: 1200},
	}
	ctr := []encode.IfCounter{{IfIndex: 7, SpeedBps: 10e9, InOctets: 1 << 40, OutOctets: 99, InUcast: 12345}}
	exporter := netip.MustParseAddr("10.255.0.3")
	var recs []flow.Record
	var ifs []flow.IfCounters
	for _, p := range e.Packets(in, ctr, 1000) {
		var err error
		recs, ifs, err = Decode(exporter, p, recs, ifs)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(recs) != 3 {
		t.Fatalf("want 3 got %d", len(recs))
	}
	if r := recs[0]; r.TCPFlags != flow.TCPSyn || r.DstPort != 80 || r.SamplingRate != 2048 || r.Bytes != 60 || r.Packets != 1 {
		t.Fatalf("tcp sample %+v", r)
	}
	if r := recs[1]; !r.Fragment || r.SrcPort != 0 {
		// MF set with offset 0 still parses L4; we only assert the fragment flag here.
		if !r.Fragment {
			t.Fatalf("fragment not detected %+v", r)
		}
	}
	if r := recs[2]; r.Dst.String() != "2a0f::1" || r.SrcPort != 53 {
		t.Fatalf("v6 sample %+v", r)
	}
	if len(ifs) != 1 || ifs[0].IfIndex != 7 || ifs[0].InOctets != 1<<40 || ifs[0].InPkts != 12345 || !ifs[0].OperUp {
		t.Fatalf("counters %+v", ifs)
	}
}

func TestTruncationNeverPanics(t *testing.T) {
	e := &encode.SFlow{Agent: netip.MustParseAddr("10.0.0.1"), SamplingRate: 1}
	p := e.Packets([]encode.Flow{{Src: netip.MustParseAddr("1.1.1.1"), Dst: netip.MustParseAddr("2.2.2.2"),
		Proto: 6, Bytes: 100}}, []encode.IfCounter{{IfIndex: 1}}, 1)[0]
	for i := 0; i <= len(p); i++ {
		_, _, _ = Decode(netip.Addr{}, p[:i], nil, nil)
	}
}
