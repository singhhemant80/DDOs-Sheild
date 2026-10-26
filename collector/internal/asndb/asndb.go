// Package asndb maps source addresses to their origin AS and country, from the iptoasn.com
// "ip2asn-combined" table (gzip TSV: range_start, range_end, AS_number, country, description)
// that Shield downloads daily. The collector uses it to total attack traffic per source network
// over every source, not only the busiest ones it lists individually.
package asndb

import (
	"bufio"
	"compress/gzip"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	Unknown uint32 = 4294967294 // no table, or the address is in no range
	Other   uint32 = 4294967295 // aggregate of networks beyond the per-window limit
)

type rng4 struct {
	start, end uint32
	asn        uint32
	cc         [2]byte
}

type rng6 struct {
	start, end netip.Addr
	asn        uint32
	cc         [2]byte
}

type Table struct {
	v4    []rng4
	v6    []rng6
	mtime time.Time
}

func (t *Table) Len() int { return len(t.v4) + len(t.v6) }

// Lookup returns the origin AS (0 = not routed) and country of a, or Unknown.
func (t *Table) Lookup(a netip.Addr) (uint32, string) {
	if t == nil {
		return Unknown, ""
	}
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		i := sort.Search(len(t.v4), func(i int) bool { return t.v4[i].start > n }) - 1
		if i >= 0 && n <= t.v4[i].end {
			return t.v4[i].asn, cc(t.v4[i].cc)
		}
		return Unknown, ""
	}
	i := sort.Search(len(t.v6), func(i int) bool { return t.v6[i].start.Compare(a) > 0 }) - 1
	if i >= 0 && a.Compare(t.v6[i].end) <= 0 {
		return t.v6[i].asn, cc(t.v6[i].cc)
	}
	return Unknown, ""
}

func cc(b [2]byte) string {
	if b[0] == 0 {
		return ""
	}
	return string(b[:])
}

// Load reads a gzip TSV table.
func Load(path string) (*Table, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, _ := f.Stat()
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer z.Close()
	t := &Table{}
	if st != nil {
		t.mtime = st.ModTime()
	}
	sc := bufio.NewScanner(z)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		p := strings.SplitN(sc.Text(), "\t", 5)
		if len(p) < 4 {
			continue
		}
		a, err1 := netip.ParseAddr(p[0])
		b, err2 := netip.ParseAddr(p[1])
		asn, err3 := strconv.ParseUint(p[2], 10, 32)
		if err1 != nil || err2 != nil || err3 != nil || a.Is4() != b.Is4() {
			continue
		}
		var c [2]byte
		if asn != 0 && len(p[3]) == 2 && p[3] != "No" {
			c = [2]byte{p[3][0], p[3][1]}
		}
		if a.Is4() {
			x, y := a.As4(), b.As4()
			t.v4 = append(t.v4, rng4{uint32(x[0])<<24 | uint32(x[1])<<16 | uint32(x[2])<<8 | uint32(x[3]),
				uint32(y[0])<<24 | uint32(y[1])<<16 | uint32(y[2])<<8 | uint32(y[3]), uint32(asn), c})
		} else {
			t.v6 = append(t.v6, rng6{a, b, uint32(asn), c})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(t.v4, func(i, j int) bool { return t.v4[i].start < t.v4[j].start })
	sort.Slice(t.v6, func(i, j int) bool { return t.v6[i].start.Less(t.v6[j].start) })
	return t, nil
}

// Holder keeps the current table and reloads it when the file changes.
type Holder struct{ v atomic.Pointer[Table] }

func (h *Holder) Load() *Table { return h.v.Load() }

// Refresh loads path if it changed since the current table was read. Returns whether it loaded.
func (h *Holder) Refresh(path string) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if cur := h.v.Load(); cur != nil && cur.mtime.Equal(st.ModTime()) {
		return false, nil
	}
	t, err := Load(path)
	if err != nil {
		return false, err
	}
	h.v.Store(t)
	return true, nil
}
