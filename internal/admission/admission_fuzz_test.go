package admission

import (
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func FuzzClientIP(f *testing.F) {
	f.Add("198.51.100.7, 10.1.1.1")
	f.Add("garbage\n198.51.100.7")
	f.Add("")
	f.Fuzz(func(t *testing.T, forwarded string) {
		if len(forwarded) > 1024 {
			return
		}
		trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8")}
		r := &http.Request{RemoteAddr: "[::ffff:203.0.113.7]:80", Header: make(http.Header)}
		for value := range strings.SplitSeq(forwarded, "\n") {
			r.Header.Add("X-Forwarded-For", value)
		}
		if got := ClientIP(r, trusted); got != netip.MustParseAddr("203.0.113.7") {
			t.Fatal("untrusted peer changed its identity through headers")
		}
		r.RemoteAddr = "127.0.0.1:80"
		// Compare the allocation-free walk against the original joined-header
		// semantics, including empty lines, malformed hops, and repeated fields.
		want := netip.MustParseAddr("127.0.0.1")
		hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for _, raw := range slices.Backward(hops) {
			hop, err := netip.ParseAddr(strings.TrimSpace(raw))
			if err != nil {
				break
			}
			want = hop.Unmap()
			if !isTrusted(want, trusted) {
				break
			}
		}
		if got := ClientIP(r, trusted); got != want {
			t.Fatalf("forwarded %q: got %s, want %s", forwarded, got, want)
		}
		r.Header.Add("X-Forwarded-For", "198.51.100.7, 10.1.1.1")
		if got := ClientIP(r, trusted); got != netip.MustParseAddr("198.51.100.7") {
			t.Fatal("untrusted prefix changed the first untrusted hop from the right")
		}
	})
}

func FuzzAdmissionGate(f *testing.F) {
	f.Add([]byte{2, 1, 0, 0, 0, 0, 0, 1, 1, 0})
	f.Add([]byte{0, 0, 0, 0, 1, 0, 1, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 {
			return
		}
		maxTotal, perIP := int(data[0]%16)+1, int(data[1]%8)+1
		g := NewGate(maxTotal, perIP)
		var held []netip.Addr
		for i := 2; i+1 < min(len(data), 258); i += 2 {
			ip := netip.AddrFrom4([4]byte{192, 0, 2, data[i+1] % 8})
			index := slices.Index(held, ip)
			if data[i]%2 == 1 {
				if index >= 0 {
					g.Release(ip)
					held = slices.Delete(held, index, index+1)
				}
			} else {
				count := 0
				for _, owner := range held {
					if owner == ip {
						count++
					}
				}
				want := Admitted
				if len(held) >= maxTotal {
					want = GlobalFull
				} else if count >= perIP {
					want = PerIPFull
				}
				if got := g.Acquire(ip); got != want {
					t.Fatalf("step %d: admission=%d want=%d", i/2, got, want)
				}
				if want == Admitted {
					held = append(held, ip)
				}
			}
			owners := slices.Clone(held)
			slices.SortFunc(owners, func(a, b netip.Addr) int { return a.Compare(b) })
			if total, ips := g.Stats(); total != len(held) || ips != len(slices.Compact(owners)) {
				t.Fatalf("step %d: admission resources disagree with model", i/2)
			}
		}
		for _, ip := range held {
			g.Release(ip)
		}
		if total, ips := g.Stats(); total != 0 || ips != 0 {
			t.Fatalf("cleanup retained %d slots and %d addresses", total, ips)
		}
	})
}
