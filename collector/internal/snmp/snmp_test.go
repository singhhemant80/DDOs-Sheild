package snmp

import (
	"net"
	"testing"
	"time"
)

func TestOIDRoundTrip(t *testing.T) {
	for _, s := range []string{"1.3.6.1.2.1.31.1.1.1.6.1", "1.3.6.1.2.1.2.2.1.8.4294967295", "1.3.6.1.4.1.14988.1"} {
		o, err := ParseOID(s)
		if err != nil {
			t.Fatal(err)
		}
		_, v, _, _ := readTLV(encOID(o))
		if got := decOID(v); got != s {
			t.Fatalf("%s -> %s", s, got)
		}
	}
}

// fakeAgent answers GetRequests with fixed values, verifying the community.
func fakeAgent(t *testing.T, community string, vals map[string]any) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			c, id, oids, err := DecodeGetRequest(buf[:n])
			if err != nil || c != community {
				continue // wrong community: real agents stay silent
			}
			var out [][2]any
			for _, o := range oids {
				out = append(out, [2]any{o, vals[o]})
			}
			pc.WriteTo(EncodeResponse(c, id, out), addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestGetAgainstFakeAgent(t *testing.T) {
	addr := fakeAgent(t, "s3cret", map[string]any{
		"1.3.6.1.2.1.31.1.1.1.6.3":  uint64(1 << 50),
		"1.3.6.1.2.1.31.1.1.1.15.3": uint32(10000),
		"1.3.6.1.2.1.31.1.1.1.1.3":  "sfp-sfpplus1",
		"1.3.6.1.2.1.2.2.1.8.3":     1,
	})
	c := &Client{Target: addr, Community: "s3cret", Timeout: time.Second}
	v, err := c.Get([]string{"1.3.6.1.2.1.31.1.1.1.6.3", "1.3.6.1.2.1.31.1.1.1.15.3",
		"1.3.6.1.2.1.31.1.1.1.1.3", "1.3.6.1.2.1.2.2.1.8.3", "1.3.6.1.2.1.31.1.1.1.10.3"})
	if err != nil {
		t.Fatal(err)
	}
	if v["1.3.6.1.2.1.31.1.1.1.6.3"].Uint != 1<<50 || v["1.3.6.1.2.1.31.1.1.1.15.3"].Uint != 10000 ||
		string(v["1.3.6.1.2.1.31.1.1.1.1.3"].Bytes) != "sfp-sfpplus1" || v["1.3.6.1.2.1.2.2.1.8.3"].Uint != 1 {
		t.Fatalf("%+v", v)
	}
	if !v["1.3.6.1.2.1.31.1.1.1.10.3"].Missing() {
		t.Fatal("unknown OID must decode as noSuchInstance")
	}
	bad := &Client{Target: addr, Community: "wrong", Timeout: 200 * time.Millisecond}
	if _, err := bad.Get([]string{"1.3.6.1.2.1.31.1.1.1.6.3"}); err == nil {
		t.Fatal("wrong community must time out")
	}
}

func TestDecodeGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, {0x30}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, {0x30, 0x02, 0x02, 0x05}} {
		if _, _, _, err := DecodeResponse(b); err == nil {
			t.Fatalf("expected error for %x", b)
		}
	}
}
