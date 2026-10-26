// Package sflow decodes sFlow v5 datagrams (flow samples + generic interface counters).
package sflow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"shield/collector/internal/flow"
)

var (
	ErrShort   = errors.New("sflow: truncated")
	ErrVersion = errors.New("sflow: unsupported version")
)

const (
	fmtFlowSample        = 1
	fmtCounterSample     = 2
	fmtFlowSampleExp     = 3
	fmtCounterSampleExp  = 4
	recRawHeader         = 1
	recSampledIPv4       = 3
	recSampledIPv6       = 4
	recGenericIfCounters = 1
	hdrProtoEthernet     = 1
	hdrProtoIPv4         = 11
	hdrProtoIPv6         = 12
	maxSamples           = 4096
	maxRecords           = 256
)

type reader struct {
	b   []byte
	err error
}

func (r *reader) u32() uint32 {
	if r.err != nil || len(r.b) < 4 {
		r.err = ErrShort
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *reader) u64() uint64 {
	if r.err != nil || len(r.b) < 8 {
		r.err = ErrShort
		return 0
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil || n < 0 || len(r.b) < n {
		r.err = ErrShort
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) addr() netip.Addr {
	switch r.u32() {
	case 1:
		b := r.bytes(4)
		if b == nil {
			return netip.Addr{}
		}
		return netip.AddrFrom4([4]byte(b))
	case 2:
		b := r.bytes(16)
		if b == nil {
			return netip.Addr{}
		}
		return netip.AddrFrom16([16]byte(b))
	default:
		r.err = fmt.Errorf("sflow: unknown address type")
		return netip.Addr{}
	}
}

// Decode parses one datagram. exporter is the UDP source; the sFlow agent address in the
// datagram is used for interface counters (it identifies the device, not the socket).
func Decode(exporter netip.Addr, pkt []byte, recs []flow.Record, ifs []flow.IfCounters) ([]flow.Record, []flow.IfCounters, error) {
	r := &reader{b: pkt}
	if r.u32() != 5 {
		if r.err != nil {
			return recs, ifs, r.err
		}
		return recs, ifs, ErrVersion
	}
	agent := r.addr()
	r.u32() // sub-agent
	r.u32() // sequence
	r.u32() // uptime
	n := r.u32()
	if r.err != nil {
		return recs, ifs, r.err
	}
	if n > maxSamples {
		return recs, ifs, fmt.Errorf("sflow: %d samples", n)
	}
	for i := uint32(0); i < n; i++ {
		format := r.u32()
		length := int(r.u32())
		body := r.bytes(length)
		if r.err != nil {
			return recs, ifs, r.err
		}
		if format>>12 != 0 { // non-standard enterprise
			continue
		}
		var err error
		switch format & 0xfff {
		case fmtFlowSample, fmtFlowSampleExp:
			recs, err = flowSample(exporter, body, format&0xfff == fmtFlowSampleExp, recs)
		case fmtCounterSample, fmtCounterSampleExp:
			ifs, err = counterSample(agent, body, format&0xfff == fmtCounterSampleExp, ifs)
		}
		if err != nil {
			return recs, ifs, err
		}
	}
	return recs, ifs, nil
}

func flowSample(exporter netip.Addr, b []byte, expanded bool, recs []flow.Record) ([]flow.Record, error) {
	r := &reader{b: b}
	r.u32() // seq
	if expanded {
		r.u32()
		r.u32()
	} else {
		r.u32()
	}
	rate := r.u32()
	r.u32() // pool
	r.u32() // drops
	if expanded {
		r.u32()
		r.u32()
		r.u32()
		r.u32()
	} else {
		r.u32()
		r.u32()
	}
	n := r.u32()
	if r.err != nil {
		return recs, r.err
	}
	if n > maxRecords {
		return recs, fmt.Errorf("sflow: %d flow records", n)
	}
	var rec flow.Record
	have := false
	for i := uint32(0); i < n; i++ {
		format := r.u32()
		length := int(r.u32())
		body := r.bytes((length + 3) &^ 3)
		if r.err != nil {
			return recs, r.err
		}
		body = body[:length]
		if format>>12 != 0 {
			continue
		}
		switch format & 0xfff {
		case recRawHeader:
			if rec2, ok := rawHeader(body); ok && !have {
				rec, have = rec2, true
			}
		case recSampledIPv4, recSampledIPv6:
			if rec2, ok := sampledIP(body, format&0xfff == recSampledIPv6); ok && !have {
				rec, have = rec2, true
			}
		}
	}
	if !have {
		return recs, nil
	}
	rec.Kind = flow.SFlow
	rec.Exporter = exporter
	rec.SamplingRate = rate
	rec.Packets = 1
	recs = append(recs, rec)
	return recs, nil
}

func rawHeader(b []byte) (flow.Record, bool) {
	r := &reader{b: b}
	proto := r.u32()
	frameLen := r.u32()
	stripped := r.u32()
	hlen := int(r.u32())
	hdr := r.bytes(hlen)
	if r.err != nil {
		return flow.Record{}, false
	}
	var rec flow.Record
	rec.Bytes = uint64(frameLen) - uint64(min(stripped, frameLen))
	var ok bool
	switch proto {
	case hdrProtoEthernet:
		ok = parseEthernet(hdr, &rec)
	case hdrProtoIPv4:
		ok = parseIPv4(hdr, &rec)
	case hdrProtoIPv6:
		ok = parseIPv6(hdr, &rec)
	}
	return rec, ok
}

func parseEthernet(b []byte, rec *flow.Record) bool {
	if len(b) < 14 {
		return false
	}
	et := binary.BigEndian.Uint16(b[12:])
	b = b[14:]
	for i := 0; i < 2 && (et == 0x8100 || et == 0x88a8); i++ {
		if len(b) < 4 {
			return false
		}
		et = binary.BigEndian.Uint16(b[2:])
		b = b[4:]
	}
	switch et {
	case 0x0800:
		return parseIPv4(b, rec)
	case 0x86dd:
		return parseIPv6(b, rec)
	}
	return false
}

func parseIPv4(b []byte, rec *flow.Record) bool {
	if len(b) < 20 || b[0]>>4 != 4 {
		return false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 {
		return false
	}
	rec.Proto = b[9]
	rec.Src = netip.AddrFrom4([4]byte(b[12:16]))
	rec.Dst = netip.AddrFrom4([4]byte(b[16:20]))
	ff := binary.BigEndian.Uint16(b[6:])
	off := ff & 0x1fff
	rec.Fragment = ff&0x2000 != 0 || off != 0
	if off == 0 && len(b) >= ihl {
		parseL4(b[ihl:], rec)
	}
	return true
}

func parseIPv6(b []byte, rec *flow.Record) bool {
	if len(b) < 40 || b[0]>>4 != 6 {
		return false
	}
	next := b[6]
	rec.Src = netip.AddrFrom16([16]byte(b[8:24])).Unmap()
	rec.Dst = netip.AddrFrom16([16]byte(b[24:40])).Unmap()
	b = b[40:]
	for i := 0; i < 6; i++ { // walk a bounded number of extension headers
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, dest opts
			if len(b) < 8 {
				rec.Proto = next
				return true
			}
			l := (int(b[1]) + 1) * 8
			next = b[0]
			if len(b) < l {
				rec.Proto = next
				return true
			}
			b = b[l:]
			continue
		case 44: // fragment
			if len(b) < 8 {
				rec.Proto = next
				return true
			}
			rec.Fragment = true
			fo := binary.BigEndian.Uint16(b[2:]) >> 3
			next = b[0]
			b = b[8:]
			if fo != 0 {
				rec.Proto = next
				return true
			}
			continue
		}
		break
	}
	rec.Proto = next
	parseL4(b, rec)
	return true
}

func parseL4(b []byte, rec *flow.Record) {
	switch rec.Proto {
	case 6:
		if len(b) >= 14 {
			rec.SrcPort = binary.BigEndian.Uint16(b)
			rec.DstPort = binary.BigEndian.Uint16(b[2:])
			rec.TCPFlags = b[13]
		}
	case 17:
		if len(b) >= 4 {
			rec.SrcPort = binary.BigEndian.Uint16(b)
			rec.DstPort = binary.BigEndian.Uint16(b[2:])
		}
	}
}

func sampledIP(b []byte, v6 bool) (flow.Record, bool) {
	r := &reader{b: b}
	var rec flow.Record
	rec.Bytes = uint64(r.u32())
	rec.Proto = uint8(r.u32())
	if v6 {
		s, d := r.bytes(16), r.bytes(16)
		if r.err != nil {
			return rec, false
		}
		rec.Src, rec.Dst = netip.AddrFrom16([16]byte(s)).Unmap(), netip.AddrFrom16([16]byte(d)).Unmap()
	} else {
		s, d := r.bytes(4), r.bytes(4)
		if r.err != nil {
			return rec, false
		}
		rec.Src, rec.Dst = netip.AddrFrom4([4]byte(s)), netip.AddrFrom4([4]byte(d))
	}
	rec.SrcPort = uint16(r.u32())
	rec.DstPort = uint16(r.u32())
	rec.TCPFlags = uint8(r.u32())
	return rec, r.err == nil
}

func counterSample(agent netip.Addr, b []byte, expanded bool, ifs []flow.IfCounters) ([]flow.IfCounters, error) {
	r := &reader{b: b}
	r.u32()
	if expanded {
		r.u32()
		r.u32()
	} else {
		r.u32()
	}
	n := r.u32()
	if r.err != nil {
		return ifs, r.err
	}
	if n > maxRecords {
		return ifs, fmt.Errorf("sflow: %d counter records", n)
	}
	for i := uint32(0); i < n; i++ {
		format := r.u32()
		length := int(r.u32())
		body := r.bytes(length)
		if r.err != nil {
			return ifs, r.err
		}
		if format != recGenericIfCounters {
			continue
		}
		c := &reader{b: body}
		var ic flow.IfCounters
		ic.Agent = agent
		ic.IfIndex = c.u32()
		c.u32() // type
		ic.SpeedBps = c.u64()
		c.u32() // direction
		ic.OperUp = c.u32()&0x2 != 0
		ic.InOctets = c.u64()
		ic.InPkts = uint64(c.u32()) // unicast only: the three 32-bit counters wrap independently
		c.u32()
		c.u32()
		c.u32()
		c.u32()
		c.u32()
		ic.OutOctets = c.u64()
		ic.OutPkts = uint64(c.u32())
		c.u32()
		c.u32()
		ic.Width32Pkts = true
		if c.err != nil {
			return ifs, c.err
		}
		ifs = append(ifs, ic)
	}
	return ifs, nil
}
