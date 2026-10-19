package admission

import (
	"net/http"
	"net/netip"
	"testing"
)

func BenchmarkClientIP(b *testing.B) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8")}
	for _, tc := range []struct {
		name   string
		remote string
		xff    []string
	}{
		{"direct", "198.51.100.7:1234", nil},
		{"proxy", "127.0.0.1:1234", []string{"198.51.100.7"}},
		{"chain", "127.0.0.1:1234", []string{"6.6.6.6, 198.51.100.7, 10.1.1.1"}},
		{"headers", "127.0.0.1:1234", []string{"6.6.6.6", "198.51.100.7, 10.1.1.1"}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			r := &http.Request{RemoteAddr: tc.remote, Header: http.Header{"X-Forwarded-For": tc.xff}}
			want := netip.MustParseAddr("198.51.100.7")
			b.ReportAllocs()
			for b.Loop() {
				if got := ClientIP(r, trusted); got != want {
					b.Fatalf("client IP %s, want %s", got, want)
				}
			}
		})
	}
}
