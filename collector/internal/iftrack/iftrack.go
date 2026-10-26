// Package iftrack converts cumulative interface counters into rates.
package iftrack

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"shield/collector/internal/flow"
)

type Rate struct {
	Agent      netip.Addr `json:"-"`
	AgentStr   string     `json:"agent"`
	IfIndex    uint32     `json:"if_index"`
	IfName     string     `json:"if_name,omitempty"`
	SpeedBps   uint64     `json:"speed_bps"`
	OperUp     bool       `json:"oper_up"`
	InBps      float64    `json:"in_bps"`
	OutBps     float64    `json:"out_bps"`
	InPps      float64    `json:"in_pps"`
	OutPps     float64    `json:"out_pps"`
	InUtil     float64    `json:"in_util"`  // 0..1, 0 if speed unknown
	OutUtil    float64    `json:"out_util"` // 0..1
	TS         int64      `json:"ts"`
	Source     string     `json:"source"` // "sflow" | "snmp"
	Provenance string     `json:"provenance"`
}

type key struct {
	agent netip.Addr
	idx   uint32
}

type last struct {
	at time.Time
	c  flow.IfCounters
}

type Tracker struct {
	mu   sync.Mutex
	prev map[key]last
	// MinInterval ignores samples arriving faster than this (duplicates from multiple collectors).
	MinInterval time.Duration
	// MaxInterval discards deltas over gaps longer than this (rate would be meaningless).
	MaxInterval time.Duration
}

func New() *Tracker {
	return &Tracker{prev: map[key]last{}, MinInterval: 500 * time.Millisecond, MaxInterval: 10 * time.Minute}
}

// Update returns a rate once two samples are available. ok=false on first sample or reset.
func (t *Tracker) Update(c flow.IfCounters, at time.Time, source, name string) (Rate, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := key{c.Agent, c.IfIndex}
	p, have := t.prev[k]
	if have && at.Sub(p.at) < t.MinInterval {
		return Rate{}, false
	}
	t.prev[k] = last{at, c}
	if !have {
		return Rate{}, false
	}
	dt := at.Sub(p.at).Seconds()
	if dt <= 0 || at.Sub(p.at) > t.MaxInterval {
		return Rate{}, false
	}
	// 64-bit octet counters going backwards = device reboot/counter reset, not a wrap.
	if c.InOctets < p.c.InOctets || c.OutOctets < p.c.OutOctets {
		return Rate{}, false
	}
	r := Rate{
		Agent: c.Agent, AgentStr: c.Agent.String(), IfIndex: c.IfIndex, IfName: name,
		SpeedBps: c.SpeedBps, OperUp: c.OperUp, TS: at.Unix(), Source: source, Provenance: "measured",
		InBps:  float64(c.InOctets-p.c.InOctets) * 8 / dt,
		OutBps: float64(c.OutOctets-p.c.OutOctets) * 8 / dt,
		InPps:  float64(delta(p.c.InPkts, c.InPkts, c.Width32Pkts)) / dt,
		OutPps: float64(delta(p.c.OutPkts, c.OutPkts, c.Width32Pkts)) / dt,
	}
	if c.SpeedBps > 0 {
		r.InUtil = r.InBps / float64(c.SpeedBps)
		r.OutUtil = r.OutBps / float64(c.SpeedBps)
	}
	return r, true
}

func delta(old, cur uint64, w32 bool) uint64 {
	if cur >= old {
		return cur - old
	}
	if w32 {
		return (1<<32 - old) + cur
	}
	return 0
}

func (r Rate) Key() string { return fmt.Sprintf("%s|%d", r.AgentStr, r.IfIndex) }
