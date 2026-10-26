// Package netflow decodes NetFlow v9 (RFC 3954) and IPFIX (RFC 7011) export packets.
//
// Templates and sampling parameters are cached per (exporter, observation domain / source ID).
// Data records that arrive before their template are counted and dropped (MissingTemplate).
package netflow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"shield/collector/internal/flow"
)

// Information element IDs (shared numbering between v9 and IPFIX for these).
const (
	ieOctetDelta      = 1
	iePacketDelta     = 2
	ieProtocol        = 4
	ieTCPFlags        = 6
	ieSrcPort         = 7
	ieSrcIPv4         = 8
	ieDstPort         = 11
	ieDstIPv4         = 12
	ieLastSwitched    = 21
	ieFirstSwitched   = 22
	ieOutBytes        = 23 // v9 OUT_BYTES
	ieOutPkts         = 24 // v9 OUT_PKTS
	ieSrcIPv6         = 27
	ieDstIPv6         = 28
	ieSamplingIntv    = 34
	ieSamplerRandom   = 50
	ieOctetTotal      = 85
	iePacketTotal     = 86
	ieFragmentOffset  = 88
	ieFlowStartSec    = 150
	ieFlowEndSec      = 151
	ieFlowStartMs     = 152
	ieFlowEndMs       = 153
	ieFragmentFlags   = 197
	iePktInterval     = 305
	iePktSpace        = 306
	variableLength    = 0xFFFF
	enterpriseBit     = 0x8000
	maxTemplateFields = 512
)

var (
	ErrShort   = errors.New("packet truncated")
	ErrVersion = errors.New("unsupported version")
)

type field struct {
	id         uint16
	length     uint16
	enterprise bool
}

type template struct {
	fields     []field
	scopeCount int // >0 for options templates
	isOptions  bool
	seen       time.Time
}

type domainKey struct {
	exporter netip.Addr
	version  uint16
	domain   uint32
}

type tmplKey struct {
	domainKey
	id uint16
}

// Stats are cumulative counters, safe to read via Snapshot.
type Stats struct {
	Packets, Records, Templates, OptionsRecords, MissingTemplate, Malformed uint64
}

// Decoder is safe for concurrent use.
type Decoder struct {
	mu        sync.Mutex
	templates map[tmplKey]*template
	sampling  map[domainKey]uint32
	stats     Stats
	// TemplateTTL drops templates not refreshed for this long (exporter restarts).
	TemplateTTL time.Duration
	now         func() time.Time
}

func NewDecoder() *Decoder {
	return &Decoder{
		templates:   map[tmplKey]*template{},
		sampling:    map[domainKey]uint32{},
		TemplateTTL: 30 * time.Minute,
		now:         time.Now,
	}
}

func (d *Decoder) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stats
}

// SamplingRate reports the rate learned from options data for an exporter (0 if unknown).
func (d *Decoder) SamplingRate(exporter netip.Addr) uint32 {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, v := range d.sampling {
		if k.exporter == exporter {
			return v
		}
	}
	return 0
}

// Decode parses one UDP payload and appends flow records to out.
func (d *Decoder) Decode(exporter netip.Addr, pkt []byte, out []flow.Record) ([]flow.Record, error) {
	if len(pkt) < 4 {
		return out, ErrShort
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stats.Packets++
	var err error
	switch binary.BigEndian.Uint16(pkt) {
	case 9:
		out, err = d.decodeV9(exporter, pkt, out)
	case 10:
		out, err = d.decodeIPFIX(exporter, pkt, out)
	default:
		err = ErrVersion
	}
	if err != nil {
		d.stats.Malformed++
	}
	return out, err
}

type hdrInfo struct {
	unixSecs uint32
	uptimeMs uint32 // v9 only
}

func (d *Decoder) decodeV9(exporter netip.Addr, p []byte, out []flow.Record) ([]flow.Record, error) {
	if len(p) < 20 {
		return out, ErrShort
	}
	h := hdrInfo{uptimeMs: binary.BigEndian.Uint32(p[4:]), unixSecs: binary.BigEndian.Uint32(p[8:])}
	dk := domainKey{exporter, 9, binary.BigEndian.Uint32(p[16:])}
	b := p[20:]
	for len(b) >= 4 {
		setID := binary.BigEndian.Uint16(b)
		setLen := int(binary.BigEndian.Uint16(b[2:]))
		if setID == 0 && setLen == 0 {
			break // trailing zero padding
		}
		if setLen < 4 || setLen > len(b) {
			return out, fmt.Errorf("v9 flowset length %d: %w", setLen, ErrShort)
		}
		body := b[4:setLen]
		var err error
		switch {
		case setID == 0:
			err = d.parseTemplates(dk, body, false, false)
		case setID == 1:
			err = d.parseTemplates(dk, body, true, false)
		case setID >= 256:
			out, err = d.parseData(dk, setID, body, h, out)
		}
		if err != nil {
			return out, err
		}
		b = b[setLen:]
	}
	return out, nil
}

func (d *Decoder) decodeIPFIX(exporter netip.Addr, p []byte, out []flow.Record) ([]flow.Record, error) {
	if len(p) < 16 {
		return out, ErrShort
	}
	msgLen := int(binary.BigEndian.Uint16(p[2:]))
	if msgLen < 16 || msgLen > len(p) {
		return out, fmt.Errorf("ipfix message length %d: %w", msgLen, ErrShort)
	}
	p = p[:msgLen]
	h := hdrInfo{unixSecs: binary.BigEndian.Uint32(p[4:])}
	dk := domainKey{exporter, 10, binary.BigEndian.Uint32(p[12:])}
	b := p[16:]
	for len(b) >= 4 {
		setID := binary.BigEndian.Uint16(b)
		setLen := int(binary.BigEndian.Uint16(b[2:]))
		if setLen < 4 || setLen > len(b) {
			return out, fmt.Errorf("ipfix set length %d: %w", setLen, ErrShort)
		}
		body := b[4:setLen]
		var err error
		switch {
		case setID == 2:
			err = d.parseTemplates(dk, body, false, true)
		case setID == 3:
			err = d.parseTemplates(dk, body, true, true)
		case setID >= 256:
			out, err = d.parseData(dk, setID, body, h, out)
		}
		if err != nil {
			return out, err
		}
		b = b[setLen:]
	}
	return out, nil
}

func (d *Decoder) parseTemplates(dk domainKey, b []byte, options, ipfix bool) error {
	for {
		minHdr := 4
		if options {
			minHdr = 6
		}
		if len(b) < minHdr {
			return nil // trailing padding
		}
		id := binary.BigEndian.Uint16(b)
		if id < 256 {
			return nil // padding
		}
		var fields []field
		var scope int
		var nFields int
		pos := 0
		if options && !ipfix {
			// v9: scope length and option length are in BYTES.
			scopeLen := int(binary.BigEndian.Uint16(b[2:]))
			optLen := int(binary.BigEndian.Uint16(b[4:]))
			if scopeLen%4 != 0 || optLen%4 != 0 {
				return fmt.Errorf("v9 options template lengths not multiple of 4")
			}
			scope = scopeLen / 4
			nFields = scope + optLen/4
			pos = 6
		} else {
			nFields = int(binary.BigEndian.Uint16(b[2:]))
			pos = 4
			if options {
				scope = int(binary.BigEndian.Uint16(b[4:]))
				pos = 6
			}
			if nFields == 0 { // IPFIX template withdrawal
				delete(d.templates, tmplKey{dk, id})
				b = b[pos:]
				continue
			}
		}
		if nFields > maxTemplateFields {
			return fmt.Errorf("template %d has %d fields", id, nFields)
		}
		fields = make([]field, 0, nFields)
		for i := 0; i < nFields; i++ {
			if len(b) < pos+4 {
				return ErrShort
			}
			f := field{id: binary.BigEndian.Uint16(b[pos:]), length: binary.BigEndian.Uint16(b[pos+2:])}
			pos += 4
			if ipfix && f.id&enterpriseBit != 0 {
				if len(b) < pos+4 {
					return ErrShort
				}
				f.id &^= enterpriseBit
				f.enterprise = true
				pos += 4
			}
			if !ipfix && f.length == variableLength {
				return fmt.Errorf("variable-length field in v9 template")
			}
			fields = append(fields, f)
		}
		d.templates[tmplKey{dk, id}] = &template{fields: fields, scopeCount: scope, isOptions: options, seen: d.now()}
		d.stats.Templates++
		b = b[pos:]
	}
}

func (d *Decoder) parseData(dk domainKey, id uint16, b []byte, h hdrInfo, out []flow.Record) ([]flow.Record, error) {
	t := d.templates[tmplKey{dk, id}]
	if t == nil || (d.TemplateTTL > 0 && d.now().Sub(t.seen) > d.TemplateTTL) {
		d.stats.MissingTemplate++
		return out, nil
	}
	minLen := 0
	for _, f := range t.fields {
		if f.length != variableLength {
			minLen += int(f.length)
		} else {
			minLen++
		}
	}
	if minLen == 0 {
		return out, nil
	}
	for len(b) >= minLen {
		var r flow.Record
		var opt optionValues
		pos := 0
		var first, last uint64
		var haveFirst, haveLast bool
		var tsUnit uint8 // 0 sysuptime ms, 1 epoch ms, 2 epoch s
		var fragOff uint64
		var fragFlags uint64
		for i, f := range t.fields {
			l := int(f.length)
			if f.length == variableLength {
				if pos >= len(b) {
					return out, ErrShort
				}
				l = int(b[pos])
				pos++
				if l == 255 {
					if pos+2 > len(b) {
						return out, ErrShort
					}
					l = int(binary.BigEndian.Uint16(b[pos:]))
					pos += 2
				}
			}
			if pos+l > len(b) {
				return out, ErrShort
			}
			v := b[pos : pos+l]
			pos += l
			if f.enterprise {
				continue
			}
			if t.isOptions {
				if i >= t.scopeCount {
					opt.set(f.id, v)
				}
				continue
			}
			switch f.id {
			case ieOctetDelta:
				r.Bytes = uintN(v)
			case iePacketDelta:
				r.Packets = uintN(v)
			case ieOctetTotal, ieOutBytes:
				if r.Bytes == 0 {
					r.Bytes = uintN(v)
				}
			case iePacketTotal, ieOutPkts:
				if r.Packets == 0 {
					r.Packets = uintN(v)
				}
			case ieProtocol:
				r.Proto = uint8(uintN(v))
			case ieTCPFlags:
				r.TCPFlags = uint8(uintN(v)) // low byte carries the classic flags
			case ieSrcPort:
				r.SrcPort = uint16(uintN(v))
			case ieDstPort:
				r.DstPort = uint16(uintN(v))
			case ieSrcIPv4, ieSrcIPv6:
				r.Src = addr(v)
			case ieDstIPv4, ieDstIPv6:
				r.Dst = addr(v)
			case ieFirstSwitched:
				first, haveFirst, tsUnit = uintN(v), true, 0
			case ieLastSwitched:
				last, haveLast, tsUnit = uintN(v), true, 0
			case ieFlowStartMs:
				first, haveFirst, tsUnit = uintN(v), true, 1
			case ieFlowEndMs:
				last, haveLast, tsUnit = uintN(v), true, 1
			case ieFlowStartSec:
				first, haveFirst, tsUnit = uintN(v), true, 2
			case ieFlowEndSec:
				last, haveLast, tsUnit = uintN(v), true, 2
			case ieFragmentOffset:
				fragOff = uintN(v)
			case ieFragmentFlags:
				fragFlags = uintN(v)
			case ieSamplingIntv, ieSamplerRandom, iePktInterval, iePktSpace:
				opt.set(f.id, v) // some exporters put sampling in every data record
			}
		}
		b = b[pos:]
		if t.isOptions {
			d.stats.OptionsRecords++
			if rate := opt.rate(); rate > 0 {
				d.sampling[dk] = rate
			}
			continue
		}
		if !r.Dst.IsValid() {
			continue // not an IP flow (e.g. L2-only template)
		}
		if rate := opt.rate(); rate > 0 {
			r.SamplingRate = rate
		} else {
			r.SamplingRate = d.sampling[dk]
		}
		if haveFirst && haveLast {
			var dur uint64
			switch tsUnit {
			case 0:
				dur = uint64(uint32(last) - uint32(first)) // wraps with sysUptime
			case 1:
				if last >= first {
					dur = last - first
				}
			case 2:
				if last >= first {
					dur = (last - first) * 1000
				}
			}
			if dur > 24*3600*1000 {
				dur = 0 // nonsense, ignore
			}
			r.DurationMs = uint32(dur)
		}
		r.Fragment = fragOff > 0 || fragFlags&0x20 != 0
		r.Exporter = dk.exporter
		if dk.version == 9 {
			r.Kind = flow.NetFlowV9
		} else {
			r.Kind = flow.IPFIX
		}
		out = append(out, r)
		d.stats.Records++
	}
	return out, nil
}

type optionValues struct {
	interval, random, pktInterval, pktSpace uint64
}

func (o *optionValues) set(id uint16, v []byte) {
	switch id {
	case ieSamplingIntv:
		o.interval = uintN(v)
	case ieSamplerRandom:
		o.random = uintN(v)
	case iePktInterval:
		o.pktInterval = uintN(v)
	case iePktSpace:
		o.pktSpace = uintN(v)
	}
}

// rate returns 1-in-N, or 0 if no sampling information is present.
func (o *optionValues) rate() uint32 {
	switch {
	case o.pktInterval > 0:
		// RFC 5476: select pktInterval packets, then skip pktSpace packets.
		return uint32((o.pktInterval + o.pktSpace) / o.pktInterval)
	case o.interval > 0:
		return uint32(o.interval)
	case o.random > 0:
		return uint32(o.random)
	}
	return 0
}

func uintN(b []byte) uint64 {
	if len(b) > 8 {
		b = b[len(b)-8:]
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

func addr(b []byte) netip.Addr {
	switch len(b) {
	case 4:
		return netip.AddrFrom4([4]byte(b))
	case 16:
		return netip.AddrFrom16([16]byte(b)).Unmap()
	}
	return netip.Addr{}
}
