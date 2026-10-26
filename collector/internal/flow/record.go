// Package flow holds the protocol-neutral types produced by the decoders.
package flow

import "net/netip"

type Kind uint8

const (
	NetFlowV9 Kind = iota + 1
	IPFIX
	SFlow
)

func (k Kind) String() string {
	switch k {
	case NetFlowV9:
		return "netflow_v9"
	case IPFIX:
		return "ipfix"
	case SFlow:
		return "sflow"
	}
	return "unknown"
}

// Record is one flow (NetFlow/IPFIX) or one sampled packet (sFlow), unscaled.
type Record struct {
	Kind     Kind
	Exporter netip.Addr
	Src, Dst netip.Addr
	SrcAS    uint32 // source AS if the exporter sends it (NetFlow/IPFIX element 16), else 0
	Proto    uint8
	SrcPort  uint16
	DstPort  uint16
	TCPFlags uint8 // OR of all packets in the flow
	Fragment bool
	Bytes    uint64
	Packets  uint64
	// SamplingRate is 1-in-N. 0 means the exporter did not tell us and no override exists:
	// figures derived from such records are labelled "estimated", not "sampled".
	SamplingRate uint32
	// DurationMs is last-first packet time, 0 if unknown or a single packet.
	DurationMs uint32
}

// IfCounters is a measured interface counter snapshot (sFlow counter sample or SNMP).
type IfCounters struct {
	Agent     netip.Addr
	IfIndex   uint32
	SpeedBps  uint64
	OperUp    bool
	InOctets  uint64
	OutOctets uint64
	InPkts    uint64
	OutPkts   uint64
	// Width32Pkts is true when packet counters are 32-bit (sFlow generic counters) and wrap at 2^32.
	Width32Pkts bool
}

const (
	TCPFin = 0x01
	TCPSyn = 0x02
	TCPRst = 0x04
	TCPPsh = 0x08
	TCPAck = 0x10
)
