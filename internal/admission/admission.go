package admission

import (
	"container/list"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	MaxEntries  = 65536
	IdleTTL     = time.Minute
	expireBatch = 64
)

type Limiter struct {
	mu      sync.Mutex
	rate    rate.Limit
	burst   int
	entries map[netip.Addr]*limiterEntry
	oldest  list.List
}

type limiterEntry struct {
	lim      *rate.Limiter
	seen     time.Time
	position *list.Element
}

func NewLimiter(r float64, burst int) *Limiter {
	return &Limiter{rate: rate.Limit(r), burst: burst, entries: map[netip.Addr]*limiterEntry{}}
}

func (l *Limiter) Allow(ip netip.Addr, now time.Time) bool {
	ip = ClientKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expire(now)
	e, ok := l.entries[ip]
	if !ok {
		if len(l.entries) >= MaxEntries {
			return false
		}
		e = &limiterEntry{lim: rate.NewLimiter(l.rate, l.burst)}
		e.position = l.oldest.PushBack(ip)
		l.entries[ip] = e
	}
	e.seen = now
	l.oldest.MoveToBack(e.position)
	return e.lim.AllowN(now, 1)
}

func (l *Limiter) expire(now time.Time) {
	for range expireBatch {
		position := l.oldest.Front()
		if position == nil {
			return
		}
		ip := position.Value.(netip.Addr)
		if now.Sub(l.entries[ip].seen) <= IdleTTL {
			return
		}
		delete(l.entries, ip)
		l.oldest.Remove(position)
	}
}

func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

type Gate struct {
	mu     sync.Mutex
	max    int
	perIP  int
	total  int
	counts map[netip.Addr]int
}

type GateResult int

const (
	Admitted GateResult = iota
	GlobalFull
	PerIPFull
)

func NewGate(max, perIP int) *Gate {
	return &Gate{max: max, perIP: perIP, counts: map[netip.Addr]int{}}
}

func (g *Gate) Acquire(ip netip.Addr) GateResult {
	ip = ClientKey(ip)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.total >= g.max {
		return GlobalFull
	}
	if g.counts[ip] >= g.perIP {
		return PerIPFull
	}
	g.total++
	g.counts[ip]++
	return Admitted
}

func (g *Gate) Release(ip netip.Addr) {
	ip = ClientKey(ip)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.total--
	if g.counts[ip] <= 1 {
		delete(g.counts, ip)
		return
	}
	g.counts[ip]--
}

func (g *Gate) Stats() (total, ips int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.total, len(g.counts)
}

func ClientKey(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	return ip
}

func ClientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	ip = ip.Unmap()
	if !isTrusted(ip, trusted) {
		return ip
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for _, hop := range slices.Backward(hops) {
		hop, err := netip.ParseAddr(strings.TrimSpace(hop))
		if err != nil {
			return ip
		}
		hop = hop.Unmap()
		if !isTrusted(hop, trusted) {
			return hop
		}
		ip = hop
	}
	return ip
}

func isTrusted(ip netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func ParsePrefixes(v string) ([]netip.Prefix, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for s := range strings.SplitSeq(v, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
