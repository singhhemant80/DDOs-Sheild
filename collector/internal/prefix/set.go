// Package prefix provides a fast "which protected prefix contains this address" lookup.
package prefix

import (
	"net/netip"
	"sort"
	"sync/atomic"
)

// Set is immutable; swap a new one in with Holder.Store.
type Set struct {
	byLen map[int]map[netip.Prefix]struct{}
	lens  []int // longest first
	all   []netip.Prefix
}

func New(ps []netip.Prefix) *Set {
	s := &Set{byLen: map[int]map[netip.Prefix]struct{}{}}
	seen := map[int]bool{}
	for _, p := range ps {
		p = p.Masked()
		if s.byLen[p.Bits()] == nil {
			s.byLen[p.Bits()] = map[netip.Prefix]struct{}{}
		}
		s.byLen[p.Bits()][p] = struct{}{}
		s.all = append(s.all, p)
		if !seen[p.Bits()] {
			seen[p.Bits()] = true
			s.lens = append(s.lens, p.Bits())
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(s.lens)))
	return s
}

// Lookup returns the most specific containing prefix.
func (s *Set) Lookup(a netip.Addr) (netip.Prefix, bool) {
	if s == nil {
		return netip.Prefix{}, false
	}
	for _, l := range s.lens {
		if l > a.BitLen() {
			continue
		}
		p, err := a.Prefix(l)
		if err != nil {
			continue
		}
		if _, ok := s.byLen[l][p]; ok {
			// IPv4 and IPv6 prefixes of the same length are distinct keys, so no cross-family match.
			return p, true
		}
	}
	return netip.Prefix{}, false
}

func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.all)
}

func (s *Set) All() []netip.Prefix { return append([]netip.Prefix(nil), s.all...) }

type Holder struct{ v atomic.Pointer[Set] }

func (h *Holder) Load() *Set   { return h.v.Load() }
func (h *Holder) Store(s *Set) { h.v.Store(s) }
