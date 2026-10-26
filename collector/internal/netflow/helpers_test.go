package netflow

import (
	"testing"

	"shield/collector/internal/flow"
)

type flowRecord = flow.Record

func (d *Decoder) decodeAll(t *testing.T, pkts [][]byte) []flow.Record {
	t.Helper()
	var out []flow.Record
	for _, p := range pkts {
		var err error
		out, err = d.Decode(exp, p, out)
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}
