package netflow

import (
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"

	"shield/collector/internal/encode"
)

var exp = netip.MustParseAddr("10.255.0.1")

func flows() []encode.Flow {
	return []encode.Flow{
		{Src: netip.MustParseAddr("198.51.100.7"), Dst: netip.MustParseAddr("163.5.191.20"), Proto: 17,
			SrcPort: 53, DstPort: 40000, Bytes: 150000, Packets: 100, DurationMs: 3000},
		{Src: netip.MustParseAddr("2001:db8::1"), Dst: netip.MustParseAddr("2a0f::20"), Proto: 6,
			SrcPort: 1234, DstPort: 443, TCPFlags: 0x02, Bytes: 600, Packets: 10},
	}
}

func TestV9RoundTripWithSamplingOptions(t *testing.T) {
	e := &encode.V9{SourceID: 7, SamplingRate: 1024, WithTemplates: true}
	pkts := e.Packets(flows(), 1_800_000_000, 5_000_000)
	d := NewDecoder()
	var recs = d.decodeAll(t, pkts)
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	r := recs[0]
	if r.Dst.String() != "163.5.191.20" || r.Src.String() != "198.51.100.7" || r.Proto != 17 ||
		r.SrcPort != 53 || r.Bytes != 150000 || r.Packets != 100 || r.DurationMs != 3000 {
		t.Fatalf("bad v4 record %+v", r)
	}
	if r.SamplingRate != 1024 {
		t.Fatalf("sampling rate from options template not applied: %d", r.SamplingRate)
	}
	if recs[1].Dst.String() != "2a0f::20" || recs[1].TCPFlags != 0x02 {
		t.Fatalf("bad v6 record %+v", recs[1])
	}
}

func TestIPFIXRoundTripPacketIntervalSpace(t *testing.T) {
	e := &encode.IPFIX{Domain: 3, SamplingRate: 512, WithTemplates: true}
	d := NewDecoder()
	recs := d.decodeAll(t, e.Packets(flows(), 1_800_000_000, 1_800_000_000_000))
	if len(recs) != 2 || recs[0].SamplingRate != 512 || recs[0].DurationMs != 3000 {
		t.Fatalf("got %+v", recs)
	}
}

func TestDataBeforeTemplateIsDroppedAndCounted(t *testing.T) {
	e := &encode.V9{SourceID: 1}
	d := NewDecoder()
	recs := d.decodeAll(t, e.Packets(flows(), 1, 1))
	if len(recs) != 0 || d.Stats().MissingTemplate == 0 {
		t.Fatalf("expected drop, got %d recs stats=%+v", len(recs), d.Stats())
	}
}

func TestTemplatesAreScopedPerExporter(t *testing.T) {
	d := NewDecoder()
	withT := &encode.V9{SourceID: 1, WithTemplates: true}
	d.decodeAll(t, withT.Packets(nil, 1, 1))
	noT := &encode.V9{SourceID: 1}
	other := netip.MustParseAddr("10.255.0.2")
	var out []flowRecord
	for _, p := range noT.Packets(flows(), 1, 1) {
		var err error
		out, err = d.Decode(other, p, out)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) != 0 {
		t.Fatal("template from one exporter must not decode another exporter's data")
	}
}

func TestUnknownSamplingIsZero(t *testing.T) {
	e := &encode.V9{SourceID: 9, WithTemplates: true}
	d := NewDecoder()
	recs := d.decodeAll(t, e.Packets(flows(), 1, 1))
	if recs[0].SamplingRate != 0 {
		t.Fatal("no options record: sampling must be unknown (0)")
	}
}

// Hand-assembled packet (independent of the encoder) to guard against symmetric bugs.
func TestV9KnownBytes(t *testing.T) {
	h := strings.Join([]string{
		"0009 0002 00000064 6b49d200 00000001 00000000",     // header: 2 records, uptime 100ms
		"0000 0014 0100 0003 0008 0004 000c 0004 0002 0004", // template 256: src4 dst4 pkts(4)
		"0100 0014 c6336407 a305bf14 00000005 00000000",     // data: 198.51.100.7 -> 163.5.191.20, 5 pkts, +pad
	}, "")
	b, err := hex.DecodeString(strings.ReplaceAll(h, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder()
	recs, err := d.Decode(exp, b, nil)
	if err != nil || len(recs) != 1 || recs[0].Packets != 5 || recs[0].Dst.String() != "163.5.191.20" {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
}

func TestTruncatedAndGarbageInputNeverPanics(t *testing.T) {
	e := &encode.IPFIX{Domain: 1, SamplingRate: 100, WithTemplates: true}
	p := e.Packets(flows(), 1, 1)[0]
	d := NewDecoder()
	for i := 0; i <= len(p); i++ {
		_, _ = d.Decode(exp, p[:i], nil)
	}
	junk := make([]byte, 300)
	for i := range junk {
		junk[i] = byte(i * 7)
	}
	junk[0], junk[1] = 0, 10
	_, _ = d.Decode(exp, junk, nil)
	junk[1] = 9
	_, _ = d.Decode(exp, junk, nil)
}

func TestV9SourceAS(t *testing.T) {
	// template 256: src4 dst4 pkts(4) src_as(4)
	h := strings.Join([]string{
		"0009 0002 00000064 6b49d200 00000001 00000000",
		"0000 0018 0100 0004 0008 0004 000c 0004 0002 0004 0010 0004",
		"0100 0014 c6336407 a305bf14 00000005 0000d6d8",
	}, "")
	b, err := hex.DecodeString(strings.ReplaceAll(h, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	recs, err := NewDecoder().Decode(exp, b, nil)
	if err != nil || len(recs) != 1 || recs[0].SrcAS != 55000 {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
}
