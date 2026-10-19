package relay

import (
	"cmp"
	"fmt"
	"slices"
	"testing"
)

func TestTopHostsMatchesFullRanking(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		tied  bool
		idle  bool
	}{
		{name: "empty"},
		{name: "one", count: 1},
		{name: "limit", count: topHostsReported},
		{name: "over limit", count: topHostsReported + 1},
		{name: "many", count: 1000},
		{name: "ties", count: 100, tied: true},
		{name: "idle", count: 100, idle: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{hosts: make(map[string]*host)}
			want := make(map[string]hostTraffic)
			var totals []int64
			for i := range tc.count {
				id := fmt.Sprintf("%016x%048x", i, i)
				total := int64((i*37 + 1) % 997)
				if tc.tied {
					total = 7
				}
				if tc.idle {
					total = 0
				}
				h := &host{pairs: make(map[string]*pair)}
				for j := range i % 4 {
					h.pairs[fmt.Sprint(j)] = nil
				}
				h.bytesIn.Store(total / 3)
				h.bytesOut.Store(total - total/3)
				s.hosts[id] = h
				if total != 0 {
					want[id[:16]] = hostTraffic{Endpoint: id[:16], BytesIn: total / 3, BytesOut: total - total/3, Pairs: len(h.pairs)}
					totals = append(totals, total)
				}
			}
			slices.SortFunc(totals, func(a, b int64) int { return cmp.Compare(b, a) })
			// Repeated map traversals exercise different candidate orders and ties.
			for range 10 {
				got := s.topHosts()
				if got == nil || len(got) != min(len(totals), topHostsReported) {
					t.Fatalf("got %v, want %d hosts (non-nil even when empty)", got, min(len(totals), topHostsReported))
				}
				seen := make(map[string]bool)
				for i, entry := range got {
					if seen[entry.Endpoint] || entry != want[entry.Endpoint] || entry.BytesIn+entry.BytesOut != totals[i] {
						t.Fatalf("rank %d: got %+v, want total %d and matching host fields", i, entry, totals[i])
					}
					seen[entry.Endpoint] = true
				}
			}
		})
	}
}
