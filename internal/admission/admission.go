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

type Keyed[K comparable] struct {
	mu      sync.Mutex
	rate    rate.Limit
	burst   int
	idle    time.Duration
	entries map[K]*limiterEntry[K]
	oldest  list.List
}

type limiterEntry[K comparable] struct {
	lim      *rate.Limiter
	seen     time.Time
	position *list.Element
}

func NewKeyed[K comparable](r float64, burst int) *Keyed[K] {
	refill := time.Duration(float64(burst) / r * float64(time.Second))
	return &Keyed[K]{rate: rate.Limit(r), burst: burst, idle: max(IdleTTL, refill), entries: map[K]*limiterEntry[K]{}}
}

func (l *Keyed[K]) Allow(key K, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expire(now)
	e, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= MaxEntries {
			return false
		}
		e = &limiterEntry[K]{lim: rate.NewLimiter(l.rate, l.burst)}
		e.position = l.oldest.PushBack(key)
		l.entries[key] = e
	}
	e.seen = now
	l.oldest.MoveToBack(e.position)
	return e.lim.AllowN(now, 1)
}

func (l *Keyed[K]) expire(now time.Time) {
	for range expireBatch {
		position := l.oldest.Front()
		if position == nil {
			return
		}
		key := position.Value.(K)
		if now.Sub(l.entries[key].seen) <= l.idle {
			return
		}
		delete(l.entries, key)
		l.oldest.Remove(position)
	}
}

func (l *Keyed[K]) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

type Limiter struct {
	*Keyed[netip.Addr]
}

func NewLimiter(r float64, burst int) *Limiter {
	return &Limiter{NewKeyed[netip.Addr](r, burst)}
}

func (l *Limiter) Allow(ip netip.Addr, now time.Time) bool {
	return l.Keyed.Allow(ClientKey(ip), now)
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
	return forwardedIP(r.Header.Values("X-Forwarded-For"), ip, trusted)
}

func forwardedIP(values []string, ip netip.Addr, trusted []netip.Prefix) netip.Addr {
	// Walk header lines and their hops from the right without joining or
	// splitting attacker-controlled headers into temporary allocations.
	for _, value := range slices.Backward(values) {
		for {
			comma := strings.LastIndexByte(value, ',')
			hop, err := netip.ParseAddr(strings.TrimSpace(value[comma+1:]))
			if err != nil {
				return ip
			}
			hop = hop.Unmap()
			if !isTrusted(hop, trusted) {
				return hop
			}
			ip = hop
			if comma < 0 {
				break
			}
			value = value[:comma]
		}
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
