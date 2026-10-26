// Package snmp implements the small subset of SNMPv2c needed to read interface counters:
// a GetRequest over UDP and BER decoding of the response. SNMPv3 is not implemented; keep
// SNMP on the management VLAN with a read-only community restricted to the Shield host.
package snmp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	tagInteger   = 0x02
	tagOctetStr  = 0x04
	tagNull      = 0x05
	tagOID       = 0x06
	tagSequence  = 0x30
	tagCounter32 = 0x41
	tagGauge32   = 0x42
	tagTimeTicks = 0x43
	tagCounter64 = 0x46
	tagNoSuchObj = 0x80
	tagNoSuchIns = 0x81
	tagEndOfMib  = 0x82
	pduGet       = 0xa0
	pduResponse  = 0xa2
)

type Value struct {
	Type  byte
	Uint  uint64
	Bytes []byte
}

func (v Value) Missing() bool {
	return v.Type == tagNoSuchObj || v.Type == tagNoSuchIns || v.Type == tagEndOfMib
}

// ---------------------------------------------------------------- BER encode

func encLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var b []byte
	for x := n; x > 0; x >>= 8 {
		b = append([]byte{byte(x)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func tlv(tag byte, v []byte) []byte { return append(append([]byte{tag}, encLen(len(v))...), v...) }

func encInt(i int64) []byte {
	b := big.NewInt(i).Bytes()
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return tlv(tagInteger, b)
}

func ParseOID(s string) ([]uint32, error) {
	parts := strings.Split(strings.TrimPrefix(s, "."), ".")
	out := make([]uint32, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bad OID %q", s)
		}
		out = append(out, uint32(v))
	}
	if len(out) < 2 {
		return nil, fmt.Errorf("bad OID %q", s)
	}
	return out, nil
}

func encOID(o []uint32) []byte {
	b := []byte{byte(o[0]*40 + o[1])}
	for _, x := range o[2:] {
		var enc []byte
		enc = append(enc, byte(x&0x7f))
		for x >>= 7; x > 0; x >>= 7 {
			enc = append([]byte{byte(x&0x7f) | 0x80}, enc...)
		}
		b = append(b, enc...)
	}
	return tlv(tagOID, b)
}

func encodeGet(community string, reqID int32, oids [][]uint32) []byte {
	var vbs []byte
	for _, o := range oids {
		vbs = append(vbs, tlv(tagSequence, append(encOID(o), tagNull, 0))...)
	}
	pdu := append(append(append(encInt(int64(reqID)), encInt(0)...), encInt(0)...), tlv(tagSequence, vbs)...)
	msg := append(append(encInt(1), tlv(tagOctetStr, []byte(community))...), tlv(pduGet, pdu)...)
	return tlv(tagSequence, msg)
}

// ---------------------------------------------------------------- BER decode

var errBER = errors.New("snmp: malformed BER")

func readTLV(b []byte) (tag byte, val, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errBER
	}
	tag = b[0]
	l := int(b[1])
	p := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return 0, nil, nil, errBER
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[2+i])
		}
		p += n
	}
	if l < 0 || len(b) < p+l {
		return 0, nil, nil, errBER
	}
	return tag, b[p : p+l], b[p+l:], nil
}

func decUint(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

func decOID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := []string{strconv.Itoa(int(b[0]) / 40), strconv.Itoa(int(b[0]) % 40)}
	var x uint64
	for _, c := range b[1:] {
		x = x<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			parts = append(parts, strconv.FormatUint(x, 10))
			x = 0
		}
	}
	return strings.Join(parts, ".")
}

// DecodeResponse returns reqID, errorStatus and OID -> value.
func DecodeResponse(b []byte) (int32, int, map[string]Value, error) {
	tag, msg, _, err := readTLV(b)
	if err != nil || tag != tagSequence {
		return 0, 0, nil, errBER
	}
	_, _, msg, err = readTLV(msg) // version
	if err != nil {
		return 0, 0, nil, err
	}
	_, _, msg, err = readTLV(msg) // community
	if err != nil {
		return 0, 0, nil, err
	}
	tag, pdu, _, err := readTLV(msg)
	if err != nil || tag != pduResponse {
		return 0, 0, nil, errBER
	}
	_, idb, pdu, err := readTLV(pdu)
	if err != nil {
		return 0, 0, nil, err
	}
	_, esb, pdu, err := readTLV(pdu)
	if err != nil {
		return 0, 0, nil, err
	}
	_, _, pdu, err = readTLV(pdu) // error index
	if err != nil {
		return 0, 0, nil, err
	}
	_, vbs, _, err := readTLV(pdu)
	if err != nil {
		return 0, 0, nil, err
	}
	out := map[string]Value{}
	for len(vbs) > 0 {
		var vb []byte
		_, vb, vbs, err = readTLV(vbs)
		if err != nil {
			return 0, 0, nil, err
		}
		_, oid, vb, err := readTLV(vb)
		if err != nil {
			return 0, 0, nil, err
		}
		vt, vv, _, err := readTLV(vb)
		if err != nil {
			return 0, 0, nil, err
		}
		v := Value{Type: vt}
		switch vt {
		case tagInteger, tagCounter32, tagGauge32, tagTimeTicks, tagCounter64:
			v.Uint = decUint(vv)
		case tagOctetStr:
			v.Bytes = append([]byte(nil), vv...)
		}
		out[decOID(oid)] = v
	}
	return int32(decUint(idb)), int(decUint(esb)), out, nil
}

// ---------------------------------------------------------------- client

type Client struct {
	Target    string // host:port
	Community string
	Timeout   time.Duration
	Retries   int
}

// Get fetches the given OIDs (max ~20 per call to stay inside one UDP datagram).
func (c *Client) Get(oids []string) (map[string]Value, error) {
	parsed := make([][]uint32, len(oids))
	for i, s := range oids {
		o, err := ParseOID(s)
		if err != nil {
			return nil, err
		}
		parsed[i] = o
	}
	conn, err := net.Dial("udp", c.Target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var rb [4]byte
	_, _ = rand.Read(rb[:])
	reqID := int32(binary.BigEndian.Uint32(rb[:]) & 0x7fffffff)
	req := encodeGet(c.Community, reqID, parsed)
	to := c.Timeout
	if to == 0 {
		to = 2 * time.Second
	}
	buf := make([]byte, 65535)
	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if _, err := conn.Write(req); err != nil {
			return nil, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(to))
		for {
			n, err := conn.Read(buf)
			if err != nil {
				lastErr = err
				break
			}
			id, status, vals, err := DecodeResponse(buf[:n])
			if err != nil || id != reqID {
				continue // stray / malformed datagram
			}
			if status != 0 {
				return nil, fmt.Errorf("snmp error-status %d", status)
			}
			return vals, nil
		}
	}
	return nil, fmt.Errorf("snmp %s: %w", c.Target, lastErr)
}

// EncodeResponse builds a GetResponse (used by tests and the lab fake agent).
func EncodeResponse(community string, reqID int32, vals [][2]any) []byte {
	var vbs []byte
	for _, kv := range vals {
		o, _ := ParseOID(kv[0].(string))
		var v []byte
		switch x := kv[1].(type) {
		case uint64:
			b := make([]byte, 9)
			binary.BigEndian.PutUint64(b[1:], x)
			v = tlv(tagCounter64, trim(b))
		case uint32:
			b := make([]byte, 5)
			binary.BigEndian.PutUint32(b[1:], x)
			v = tlv(tagGauge32, trim(b))
		case int:
			v = encInt(int64(x))
		case string:
			v = tlv(tagOctetStr, []byte(x))
		default:
			v = []byte{tagNoSuchInstance(), 0}
		}
		vbs = append(vbs, tlv(tagSequence, append(encOID(o), v...))...)
	}
	pdu := append(append(append(encInt(int64(reqID)), encInt(0)...), encInt(0)...), tlv(tagSequence, vbs)...)
	return tlv(tagSequence, append(append(encInt(1), tlv(tagOctetStr, []byte(community))...), tlv(pduResponse, pdu)...))
}

func tagNoSuchInstance() byte { return tagNoSuchIns }

func trim(b []byte) []byte {
	for len(b) > 1 && b[0] == 0 && b[1]&0x80 == 0 {
		b = b[1:]
	}
	return b
}

// DecodeGetRequest parses a GetRequest (for the fake agent in tests/lab).
func DecodeGetRequest(b []byte) (community string, reqID int32, oids []string, err error) {
	tag, msg, _, err := readTLV(b)
	if err != nil || tag != tagSequence {
		return "", 0, nil, errBER
	}
	if _, _, msg, err = readTLV(msg); err != nil {
		return
	}
	var cb []byte
	if _, cb, msg, err = readTLV(msg); err != nil {
		return
	}
	tag, pdu, _, err := readTLV(msg)
	if err != nil || tag != pduGet {
		return "", 0, nil, errBER
	}
	_, idb, pdu, err := readTLV(pdu)
	if err != nil {
		return
	}
	if _, _, pdu, err = readTLV(pdu); err != nil {
		return
	}
	if _, _, pdu, err = readTLV(pdu); err != nil {
		return
	}
	_, vbs, _, err := readTLV(pdu)
	if err != nil {
		return
	}
	for len(vbs) > 0 {
		var vb, oid []byte
		if _, vb, vbs, err = readTLV(vbs); err != nil {
			return
		}
		if _, oid, _, err = readTLV(vb); err != nil {
			return
		}
		oids = append(oids, decOID(oid))
	}
	return string(cb), int32(decUint(idb)), oids, nil
}
