// Package encode builds NetFlow v9, IPFIX and sFlow v5 packets. It exists for the lab flow
// generator (cmd/shield-flowgen) and for decoder tests; the collector never uses it.
package encode

import (
	"encoding/binary"
	"net/netip"
)

type Flow struct {
	Src, Dst         netip.Addr
	Proto            uint8
	SrcPort, DstPort uint16
	TCPFlags         uint8
	Bytes, Packets   uint64
	DurationMs       uint32
	Fragment         bool // sFlow only (sets IPv4 MF)
}

const MaxPacket = 1400

type buf []byte

func (b *buf) u8(v uint8)   { *b = append(*b, v) }
func (b *buf) u16(v uint16) { *b = binary.BigEndian.AppendUint16(*b, v) }
func (b *buf) u32(v uint32) { *b = binary.BigEndian.AppendUint32(*b, v) }
func (b *buf) u64(v uint64) { *b = binary.BigEndian.AppendUint64(*b, v) }
func (b *buf) addr(a netip.Addr) {
	s := a.AsSlice()
	*b = append(*b, s...)
}

// ---------------------------------------------------------------- NetFlow v9

const (
	v9Tmpl4   = 256
	v9Tmpl6   = 257
	v9OptTmpl = 258
)

// V9 encodes NetFlow v9. Templates (and the sampling options record when SamplingRate>0)
// are included in every packet when WithTemplates is true.
type V9 struct {
	SourceID      uint32
	SamplingRate  uint32
	WithTemplates bool
	seq           uint32
}

func v9Fields(v6 bool) [][2]uint16 {
	srcLen, srcID, dstID := uint16(4), uint16(8), uint16(12)
	if v6 {
		srcLen, srcID, dstID = 16, 27, 28
	}
	return [][2]uint16{
		{srcID, srcLen}, {dstID, srcLen}, {4, 1}, {7, 2}, {11, 2}, {6, 1}, {1, 8}, {2, 8}, {22, 4}, {21, 4},
	}
}

// Packets returns one or more export packets carrying all flows.
func (e *V9) Packets(flows []Flow, unixSecs, uptimeMs uint32) [][]byte {
	var out [][]byte
	for len(flows) > 0 || len(out) == 0 {
		var p buf
		p.u16(9)
		p.u16(0) // count, patched
		p.u32(uptimeMs)
		p.u32(unixSecs)
		p.u32(e.seq)
		p.u32(e.SourceID)
		count := 0
		if e.WithTemplates {
			start := len(p)
			p.u16(0)
			p.u16(0)
			for _, t := range []struct {
				id uint16
				v6 bool
			}{{v9Tmpl4, false}, {v9Tmpl6, true}} {
				f := v9Fields(t.v6)
				p.u16(t.id)
				p.u16(uint16(len(f)))
				for _, x := range f {
					p.u16(x[0])
					p.u16(x[1])
				}
				count++
			}
			binary.BigEndian.PutUint16(p[start+2:], uint16(len(p)-start))
			if e.SamplingRate > 0 {
				start = len(p)
				p.u16(1)
				p.u16(0)
				p.u16(v9OptTmpl)
				p.u16(4) // scope length (bytes)
				p.u16(8) // option length (bytes)
				p.u16(1) // scope: System
				p.u16(4)
				p.u16(34) // SAMPLING_INTERVAL
				p.u16(4)
				p.u16(35) // SAMPLING_ALGORITHM
				p.u16(1)
				for (len(p)-start)%4 != 0 {
					p.u8(0)
				}
				binary.BigEndian.PutUint16(p[start+2:], uint16(len(p)-start))
				count++
				start = len(p)
				p.u16(v9OptTmpl)
				p.u16(0)
				p.u32(e.SourceID)
				p.u32(e.SamplingRate)
				p.u8(2) // random
				for (len(p)-start)%4 != 0 {
					p.u8(0)
				}
				binary.BigEndian.PutUint16(p[start+2:], uint16(len(p)-start))
				count++
			}
		}
		for _, v6 := range []bool{false, true} {
			tid := uint16(v9Tmpl4)
			if v6 {
				tid = v9Tmpl6
			}
			start := -1
			rest := flows[:0:0]
			for _, f := range flows {
				if f.Dst.Is6() != v6 {
					rest = append(rest, f)
					continue
				}
				recLen := 42
				if v6 {
					recLen = 66
				}
				if len(p)+recLen+8 > MaxPacket {
					rest = append(rest, f)
					continue
				}
				if start < 0 {
					start = len(p)
					p.u16(tid)
					p.u16(0)
				}
				p.addr(f.Src)
				p.addr(f.Dst)
				p.u8(f.Proto)
				p.u16(f.SrcPort)
				p.u16(f.DstPort)
				p.u8(f.TCPFlags)
				p.u64(f.Bytes)
				p.u64(f.Packets)
				last := uptimeMs
				p.u32(last - f.DurationMs)
				p.u32(last)
				count++
			}
			if start >= 0 {
				for (len(p)-start)%4 != 0 {
					p.u8(0)
				}
				binary.BigEndian.PutUint16(p[start+2:], uint16(len(p)-start))
			}
			flows = rest
		}
		binary.BigEndian.PutUint16(p[2:], uint16(count))
		e.seq++
		out = append(out, p)
	}
	return out
}

// ---------------------------------------------------------------- IPFIX

type IPFIX struct {
	Domain        uint32
	SamplingRate  uint32 // encoded as packetInterval=1, packetSpace=rate-1
	WithTemplates bool
	seq           uint32
}

func (e *IPFIX) Packets(flows []Flow, unixSecs uint32, nowMs uint64) [][]byte {
	var out [][]byte
	for len(flows) > 0 || len(out) == 0 {
		var p buf
		p.u16(10)
		p.u16(0)
		p.u32(unixSecs)
		p.u32(e.seq)
		p.u32(e.Domain)
		if e.WithTemplates {
			start := len(p)
			p.u16(2)
			p.u16(0)
			for _, v6 := range []bool{false, true} {
				id, al, s, d := uint16(256), uint16(4), uint16(8), uint16(12)
				if v6 {
					id, al, s, d = 257, 16, 27, 28
				}
				f := [][2]uint16{{s, al}, {d, al}, {4, 1}, {7, 2}, {11, 2}, {6, 1}, {1, 8}, {2, 8}, {152, 8}, {153, 8}}
				p.u16(id)
				p.u16(uint16(len(f)))
				for _, x := range f {
					p.u16(x[0])
					p.u16(x[1])
				}
			}
			binary.BigEndian.PutUint16(p[start+2:], uint16(len(p)-start))
			if e.SamplingRate > 0 {
				start = len(p)
				p.u16(3)
				p.u16(0)
				p.u16(258)
				p.u16(3) // field count
				p.u16(1) // scope count
				p.u16(149)
				p.u16(4) // observationDomainId
				p.u16(305)
				p.u16(4)
				p.u16(306)
				p.u16(4)
				binary.BigEndian.PutUint16(p[start+2:], uint16(len(p)-start))
				start = len(p)
				p.u16(258)
				p.u16(0)
				p.u32(e.Domain)
				p.u32(1)
				p.u32(e.SamplingRate - 1)
				binary.BigEndian.PutUint16(p[start+2:], uint16(len(p)-start))
			}
		}
		for _, v6 := range []bool{false, true} {
			tid := uint16(256)
			recLen := 50
			if v6 {
				tid, recLen = 257, 74
			}
			start := -1
			rest := flows[:0:0]
			for _, f := range flows {
				if f.Dst.Is6() != v6 || len(p)+recLen+4 > MaxPacket {
					rest = append(rest, f)
					continue
				}
				if start < 0 {
					start = len(p)
					p.u16(tid)
					p.u16(0)
				}
				p.addr(f.Src)
				p.addr(f.Dst)
				p.u8(f.Proto)
				p.u16(f.SrcPort)
				p.u16(f.DstPort)
				p.u8(f.TCPFlags)
				p.u64(f.Bytes)
				p.u64(f.Packets)
				p.u64(nowMs - uint64(f.DurationMs))
				p.u64(nowMs)
			}
			if start >= 0 {
				binary.BigEndian.PutUint16(p[start+2:], uint16(len(p)-start))
			}
			flows = rest
		}
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
		e.seq++
		out = append(out, p)
	}
	return out
}

// ---------------------------------------------------------------- sFlow v5

type SFlow struct {
	Agent        netip.Addr
	SamplingRate uint32
	seq, sample  uint32
}

// IfCounter is a generic interface counter record to embed.
type IfCounter struct {
	IfIndex          uint32
	SpeedBps         uint64
	InOctets         uint64
	OutOctets        uint64
	InUcast, OutUcst uint32
}

// Packets emits one sample per entry of flows (each = one sampled packet, Bytes = frame length).
func (e *SFlow) Packets(flows []Flow, counters []IfCounter, uptimeMs uint32) [][]byte {
	var out [][]byte
	for len(flows) > 0 || len(counters) > 0 || len(out) == 0 {
		var p buf
		p.u32(5)
		if e.Agent.Is4() {
			p.u32(1)
		} else {
			p.u32(2)
		}
		p.addr(e.Agent)
		p.u32(0)
		p.u32(e.seq)
		p.u32(uptimeMs)
		nPos := len(p)
		p.u32(0)
		n := 0
		for len(counters) > 0 && len(p)+120 < MaxPacket {
			c := counters[0]
			counters = counters[1:]
			p.u32(2)
			lenPos := len(p)
			p.u32(0)
			e.sample++
			p.u32(e.sample)
			p.u32(c.IfIndex)
			p.u32(1)
			p.u32(1)
			p.u32(88)
			p.u32(c.IfIndex)
			p.u32(6)
			p.u64(c.SpeedBps)
			p.u32(1)
			p.u32(3)
			p.u64(c.InOctets)
			p.u32(c.InUcast)
			p.u32(0)
			p.u32(0)
			p.u32(0)
			p.u32(0)
			p.u32(0)
			p.u64(c.OutOctets)
			p.u32(c.OutUcst)
			p.u32(0)
			p.u32(0)
			p.u32(0)
			p.u32(0)
			p.u32(0)
			binary.BigEndian.PutUint32(p[lenPos:], uint32(len(p)-lenPos-4))
			n++
		}
		for len(flows) > 0 && len(p)+140 < MaxPacket {
			f := flows[0]
			flows = flows[1:]
			hdr := frame(f)
			p.u32(1)
			lenPos := len(p)
			p.u32(0)
			e.sample++
			p.u32(e.sample)
			p.u32(1)
			p.u32(e.SamplingRate)
			p.u32(e.sample * e.SamplingRate)
			p.u32(0)
			p.u32(1)
			p.u32(2)
			p.u32(1) // one record
			p.u32(1) // raw header
			p.u32(uint32(16 + (len(hdr)+3)&^3))
			p.u32(1) // ethernet
			p.u32(uint32(f.Bytes))
			p.u32(0)
			p.u32(uint32(len(hdr)))
			p = append(p, hdr...)
			for len(p)%4 != 0 {
				p.u8(0)
			}
			binary.BigEndian.PutUint32(p[lenPos:], uint32(len(p)-lenPos-4))
			n++
		}
		binary.BigEndian.PutUint32(p[nPos:], uint32(n))
		e.seq++
		out = append(out, p)
	}
	return out
}

// frame builds an Ethernet+IP+L4 header (first 64-ish bytes of the packet).
func frame(f Flow) []byte {
	var p buf
	p = append(p, 0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2)
	if f.Dst.Is4() {
		p.u16(0x0800)
		p.u8(0x45)
		p.u8(0)
		p.u16(uint16(f.Bytes - 14))
		p.u16(0)
		if f.Fragment {
			p.u16(0x2000)
		} else {
			p.u16(0)
		}
		p.u8(64)
		p.u8(f.Proto)
		p.u16(0)
		p.addr(f.Src)
		p.addr(f.Dst)
	} else {
		p.u16(0x86dd)
		p.u32(0x60000000)
		p.u16(uint16(f.Bytes - 54))
		p.u8(f.Proto)
		p.u8(64)
		p.addr(f.Src)
		p.addr(f.Dst)
	}
	switch f.Proto {
	case 6:
		p.u16(f.SrcPort)
		p.u16(f.DstPort)
		p.u32(1)
		p.u32(0)
		p.u8(0x50)
		p.u8(f.TCPFlags)
		p.u16(65535)
		p.u32(0)
	case 17:
		p.u16(f.SrcPort)
		p.u16(f.DstPort)
		p.u16(uint16(max(8, int(f.Bytes)-42)))
		p.u16(0)
	case 1:
		p.u8(8)
		p.u8(0)
		p.u16(0)
		p.u32(0)
	}
	return p
}
