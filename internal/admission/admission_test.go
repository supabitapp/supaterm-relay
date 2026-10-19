package admission

import (
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestLimiterBurstAndRefill(t *testing.T) {
	l := NewLimiter(10, 3)
	ip := netip.MustParseAddr("192.0.2.1")
	now := time.Unix(1000, 0)
	for i := range 3 {
		if !l.Allow(ip, now) {
			t.Fatalf("attempt %d rejected", i)
		}
	}
	if l.Allow(ip, now) {
		t.Fatal("burst exceeded")
	}
	if !l.Allow(ip, now.Add(100*time.Millisecond)) {
		t.Fatal("token not refilled")
	}
	if !l.Allow(netip.MustParseAddr("192.0.2.2"), now) {
		t.Fatal("other ip limited")
	}
}

func TestLimiterBookkeepingExpiresAndIsBounded(t *testing.T) {
	l := NewLimiter(1, 1)
	now := time.Unix(1000, 0)
	for i := range MaxEntries {
		l.Allow(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), now)
	}
	if l.Size() != MaxEntries {
		t.Fatalf("size %d", l.Size())
	}
	if l.Allow(netip.MustParseAddr("198.51.100.1"), now) {
		t.Fatal("new ip admitted while table full of live entries")
	}
	if !l.Allow(netip.MustParseAddr("198.51.100.1"), now.Add(IdleTTL+time.Second)) {
		t.Fatal("expired entries did not free capacity")
	}
	if l.Size() != MaxEntries-expireBatch+1 {
		t.Fatalf("cleanup did not respect its work budget: size %d", l.Size())
	}
	for range MaxEntries / expireBatch {
		l.Allow(netip.MustParseAddr("198.51.100.1"), now.Add(IdleTTL+time.Second))
	}
	if l.Size() != 1 || l.oldest.Len() != 1 {
		t.Fatalf("expired entries retained: entries=%d order=%d", l.Size(), l.oldest.Len())
	}
}

func TestLimiterRetainsRecentlyUsedEntries(t *testing.T) {
	l := NewLimiter(1, 1)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	now := time.Unix(1000, 0)
	l.Allow(a, now)
	l.Allow(b, now)
	l.Allow(a, now.Add(IdleTTL/2))
	l.Allow(netip.MustParseAddr("192.0.2.3"), now.Add(IdleTTL+time.Second))
	if l.entries[a] == nil || l.entries[b] != nil || l.Size() != 2 {
		t.Fatal("expiry did not preserve the recently used entry")
	}
}

func TestClientNetworkQuotas(t *testing.T) {
	for _, test := range []struct {
		name, first, same, other string
	}{
		{"mapped IPv4", "192.0.2.1", "::ffff:192.0.2.1", "192.0.2.2"},
		{"IPv6 prefix", "2001:db8:1:2::1", "2001:db8:1:2:ffff::2", "2001:db8:1:3::1"},
		{"IPv6 zone", "fe80::1%en0", "fe80::2%en1", "2001:db8::1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, same, other := netip.MustParseAddr(test.first), netip.MustParseAddr(test.same), netip.MustParseAddr(test.other)
			g := NewGate(3, 1)
			if g.Acquire(a) != Admitted || g.Acquire(same) != PerIPFull || g.Acquire(other) != Admitted {
				t.Fatal("connection quota did not isolate client networks")
			}
			g.Release(a)
			if g.Acquire(same) != Admitted {
				t.Fatal("released network quota was not reusable")
			}
			g.Release(same)
			g.Release(other)
			if total, groups := g.Stats(); total != 0 || groups != 0 {
				t.Fatalf("retained %d connections and %d client networks", total, groups)
			}
			l := NewLimiter(1, 1)
			now := time.Unix(1000, 0)
			if !l.Allow(a, now) || l.Allow(same, now) || !l.Allow(other, now) || l.Size() != 2 {
				t.Fatal("rate quota did not isolate client networks")
			}
		})
	}
}

func BenchmarkLimiterCapacity(b *testing.B) {
	for _, name := range []string{"available", "full"} {
		b.Run(name, func(b *testing.B) {
			l := NewLimiter(1, 1)
			now := time.Unix(1000, 0)
			size := MaxEntries
			if name == "available" {
				size--
			}
			ip := netip.MustParseAddr("10.0.0.0")
			for range size {
				l.Allow(ip, now)
				ip = ip.Next()
			}
			ip = netip.MustParseAddr("10.0.0.0")
			b.ResetTimer()
			for range b.N {
				l.Allow(ip, now)
			}
		})
	}
}

func TestClientIPTrustedProxies(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8")}
	req := func(remote string, xff ...string) *http.Request {
		r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	cases := []struct {
		r       *http.Request
		trusted []netip.Prefix
		want    string
	}{
		{req("203.0.113.5:1234", "1.2.3.4"), trusted, "203.0.113.5"},
		{req("127.0.0.1:1234", "198.51.100.7"), trusted, "198.51.100.7"},
		{req("127.0.0.1:1234", "6.6.6.6, 198.51.100.7, 10.1.1.1"), trusted, "198.51.100.7"},
		{req("127.0.0.1:1234", "6.6.6.6", "198.51.100.7"), trusted, "198.51.100.7"},
		{req("127.0.0.1:1234", "garbage"), trusted, "127.0.0.1"},
		{req("127.0.0.1:1234", "198.51.100.7"), nil, "127.0.0.1"},
		{req("[::ffff:127.0.0.1]:1234"), trusted, "127.0.0.1"},
		{req("127.0.0.1:1234", "", "198.51.100.7, 10.1.1.1"), trusted, "198.51.100.7"},
		{req("127.0.0.1:1234", "198.51.100.7", ""), trusted, "127.0.0.1"},
		{req("127.0.0.1:1234", "198.51.100.7,", "10.1.1.1"), trusted, "10.1.1.1"},
		{req("127.0.0.1:1234", "garbage", "10.1.1.1, 10.2.2.2"), trusted, "10.1.1.1"},
		{req("127.0.0.1:1234", "10.1.1.1", "10.2.2.2"), trusted, "10.1.1.1"},
		{req("127.0.0.1:1234", "garbage, 198.51.100.7, 10.1.1.1"), trusted, "198.51.100.7"},
		{req("127.0.0.1:1234", " \t::ffff:198.51.100.7 \t, 10.1.1.1"), trusted, "198.51.100.7"},
		{req("127.0.0.1:1234", "2001:db8::7", "10.1.1.1"), trusted, "2001:db8::7"},
	}
	for _, c := range cases {
		if got := ClientIP(c.r, c.trusted); got.String() != c.want {
			t.Errorf("%s %q: got %s want %s", c.r.RemoteAddr, c.r.Header.Values("X-Forwarded-For"), got, c.want)
		}
	}
}

func TestGateLimits(t *testing.T) {
	g := NewGate(3, 2)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	if g.Acquire(a) != Admitted || g.Acquire(a) != Admitted {
		t.Fatal("first two rejected")
	}
	if g.Acquire(a) != PerIPFull {
		t.Fatal("per-ip limit not enforced")
	}
	if g.Acquire(b) != Admitted {
		t.Fatal("other ip rejected")
	}
	if g.Acquire(b) != GlobalFull {
		t.Fatal("global limit not enforced")
	}
	g.Release(a)
	if g.Acquire(b) != Admitted {
		t.Fatal("released slot not reusable")
	}
	g.Release(a)
	g.Release(b)
	g.Release(b)
	if total, ips := g.Stats(); total != 0 || ips != 0 {
		t.Fatalf("leaked state total=%d ips=%d", total, ips)
	}
}
