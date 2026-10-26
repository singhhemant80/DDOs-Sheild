// Package metrics exposes counters and gauges in the Prometheus text format (no dependencies).
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type Registry struct {
	mu     sync.Mutex
	items  map[string]*item
	gaugeF map[string]func() float64
}

type item struct {
	help, kind string
	v          atomic.Uint64
}

func New() *Registry {
	return &Registry{items: map[string]*item{}, gaugeF: map[string]func() float64{}}
}

// Counter returns a monotonically increasing counter. name may include labels: x{a="b"}.
func (r *Registry) Counter(name, help string) *atomic.Uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if it, ok := r.items[name]; ok {
		return &it.v
	}
	it := &item{help: help, kind: "counter"}
	r.items[name] = it
	return &it.v
}

func (r *Registry) GaugeFunc(name, help string, f func() float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gaugeF[name] = f
	r.items[name] = &item{help: help, kind: "gauge"}
}

func base(n string) string {
	if i := strings.IndexByte(n, '{'); i >= 0 {
		return n[:i]
	}
	return n
}

func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	names := make([]string, 0, len(r.items))
	for n := range r.items {
		names = append(names, n)
	}
	sort.Strings(names)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	done := map[string]bool{}
	for _, n := range names {
		it := r.items[n]
		b := base(n)
		if !done[b] {
			fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", b, it.help, b, it.kind)
			done[b] = true
		}
		if f, ok := r.gaugeF[n]; ok {
			fmt.Fprintf(w, "%s %g\n", n, f())
		} else {
			fmt.Fprintf(w, "%s %d\n", n, it.v.Load())
		}
	}
	r.mu.Unlock()
}
