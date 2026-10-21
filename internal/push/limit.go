package push

import (
	"container/list"
	"crypto/ed25519"
	"slices"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	maxLimiterEntries = 65536
	expireBatch       = 64
	fullRetry         = time.Minute
)

type limiter struct {
	mu      sync.Mutex
	rate    rate.Limit
	burst   int
	idle    time.Duration
	entries map[string]*limiterEntry
	oldest  list.List
}

type limiterEntry struct {
	key      string
	lim      *rate.Limiter
	seen     time.Time
	position *list.Element
}

func newLimiter(events int, per time.Duration, burst int) *limiter {
	return &limiter{
		rate:  rate.Limit(float64(events) / per.Seconds()),
		burst: burst,
		// A bucket left alone this long has refilled, so forgetting it
		// cannot hand a caller more than a fresh bucket would.
		idle:    per * time.Duration(burst) / time.Duration(events),
		entries: map[string]*limiterEntry{},
	}
}

func (l *limiter) reserve(key string, now time.Time) (func(), time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.expire(now)
	e, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= maxLimiterEntries {
			return nil, fullRetry
		}
		e = &limiterEntry{key: key, lim: rate.NewLimiter(l.rate, l.burst)}
		e.position = l.oldest.PushBack(e)
		l.entries[key] = e
	}
	e.seen = now
	l.oldest.MoveToBack(e.position)
	r := e.lim.ReserveN(now, 1)
	if !r.OK() {
		return nil, fullRetry
	}
	if wait := r.DelayFrom(now); wait > 0 {
		r.CancelAt(now)
		return nil, wait
	}
	return func() { r.CancelAt(now) }, 0
}

func (l *limiter) expire(now time.Time) {
	for range expireBatch {
		position := l.oldest.Front()
		if position == nil {
			return
		}
		e := position.Value.(*limiterEntry)
		if now.Sub(e.seen) <= l.idle {
			return
		}
		delete(l.entries, e.key)
		l.oldest.Remove(position)
	}
}

// window admits at most limit events per key in any rolling period, which
// a token bucket cannot promise: a full bucket refilling during the period
// admits nearly twice its burst.
type window struct {
	mu      sync.Mutex
	limit   int
	period  time.Duration
	entries map[string]*windowEntry
	oldest  list.List
}

type windowEntry struct {
	key      string
	events   []time.Time
	position *list.Element
}

func newWindow(limit int, period time.Duration) *window {
	return &window{limit: limit, period: period, entries: map[string]*windowEntry{}}
}

func (w *window) reserve(key string, now time.Time) (func(), time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.expire(now)
	e, ok := w.entries[key]
	if !ok {
		if len(w.entries) >= maxLimiterEntries {
			return nil, fullRetry
		}
		e = &windowEntry{key: key}
		e.position = w.oldest.PushBack(e)
		w.entries[key] = e
	}
	start := now.Add(-w.period)
	for len(e.events) > 0 && !e.events[0].After(start) {
		e.events = e.events[1:]
	}
	if len(e.events) >= w.limit {
		return nil, e.events[0].Sub(start)
	}
	e.events = append(e.events, now)
	w.oldest.MoveToBack(e.position)
	return func() { w.cancel(e, now) }, 0
}

func (w *window) cancel(e *windowEntry, at time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, v := range slices.Backward(e.events) {
		if v.Equal(at) {
			e.events = slices.Delete(e.events, i, i+1)
			return
		}
	}
}

// expire forgets keys whose newest event left the period. The list is
// ordered by newest event, so the scan stops at the first live key.
func (w *window) expire(now time.Time) {
	for range expireBatch {
		position := w.oldest.Front()
		if position == nil {
			return
		}
		e := position.Value.(*windowEntry)
		if n := len(e.events); n > 0 && now.Sub(e.events[n-1]) < w.period {
			return
		}
		delete(w.entries, e.key)
		w.oldest.Remove(position)
	}
}

type admitter interface {
	reserve(key string, now time.Time) (cancel func(), wait time.Duration)
}

type quota struct {
	limiter admitter
	key     string
}

// take consumes one event from every quota, or from none of them, and
// reports how long the caller must wait when any quota is exhausted.
func take(now time.Time, quotas ...quota) time.Duration {
	held := make([]func(), 0, len(quotas))
	for _, q := range quotas {
		cancel, wait := q.limiter.reserve(q.key, now)
		if wait > 0 {
			for _, c := range held {
				c()
			}
			return wait
		}
		held = append(held, cancel)
	}
	return 0
}

// A replay entry holds a 64-byte signature and an expiry, about 90 bytes
// with map overhead, so a full cache stays near 23 MiB. Signatures live at
// most twice the signature window, so it admits over 400 signed requests a
// second.
const (
	maxReplayEntries = 1 << 18
	replaySweep      = 10 * time.Second
)

type signature = [ed25519.SignatureSize]byte

type replayCache struct {
	mu        sync.Mutex
	capacity  int
	seen      map[signature]int64
	nextSweep time.Time
}

func newReplayCache(capacity int) *replayCache {
	return &replayCache{capacity: capacity, seen: map[signature]int64{}}
}

// add records a signature until it leaves the timestamp window and reports
// whether it was new. A full cache refuses new signatures rather than
// forgetting live ones, and reports how long until the next sweep.
func (c *replayCache) add(sig signature, until, now time.Time) (bool, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !now.Before(c.nextSweep) {
		for s, expires := range c.seen {
			if now.UnixMilli() >= expires {
				delete(c.seen, s)
			}
		}
		c.nextSweep = now.Add(replaySweep)
	}
	if expires, ok := c.seen[sig]; ok && now.UnixMilli() < expires {
		return false, 0
	}
	if len(c.seen) >= c.capacity {
		return false, max(c.nextSweep.Sub(now), time.Second)
	}
	c.seen[sig] = until.UnixMilli()
	return true, 0
}
