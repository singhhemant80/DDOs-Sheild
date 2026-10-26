package asndb

import (
	"compress/gzip"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndLookup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.tsv.gz")
	f, _ := os.Create(p)
	z := gzip.NewWriter(f)
	z.Write([]byte("1.0.4.0\t1.0.7.255\t38803\tAU\tGTELECOM\n1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
		"192.0.2.0\t192.0.2.255\t0\tNone\tNot routed\n2001:db8::\t2001:db8::ffff\t64500\tDE\tDOC\nbad line\n"))
	z.Close()
	f.Close()
	var h Holder
	if ok, err := h.Refresh(p); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, _ := h.Refresh(p); ok {
		t.Fatal("unchanged file reloaded")
	}
	tb := h.Load()
	for _, c := range []struct {
		ip  string
		asn uint32
		cc  string
	}{{"1.0.0.7", 13335, "US"}, {"1.0.6.1", 38803, "AU"}, {"1.0.1.1", Unknown, ""}, {"192.0.2.9", 0, ""},
		{"2001:db8::5", 64500, "DE"}, {"::ffff:1.0.0.1", 13335, "US"}, {"9.9.9.9", Unknown, ""}} {
		asn, cc := tb.Lookup(netip.MustParseAddr(c.ip))
		if asn != c.asn || cc != c.cc {
			t.Errorf("%s: got %d %q want %d %q", c.ip, asn, cc, c.asn, c.cc)
		}
	}
	var nilT *Table
	if a, _ := nilT.Lookup(netip.MustParseAddr("1.0.0.1")); a != Unknown {
		t.Fatal("nil table")
	}
}
