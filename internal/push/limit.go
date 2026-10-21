package push

import (
	"container/list"
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

func (l *limiter) reserve(key string, now time.Time) (*rate.Reservation, time.Duration) {
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
	return r, 0
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

type quota struct {
	limiter *limiter
	key     string
}

// take consumes one event from every quota, or from none of them, and
// reports how long the caller must wait when any quota is exhausted.
func take(now time.Time, quotas ...quota) time.Duration {
	held := make([]*rate.Reservation, 0, len(quotas))
	for _, q := range quotas {
		r, wait := q.limiter.reserve(q.key, now)
		if wait > 0 {
			for _, h := range held {
				h.CancelAt(now)
			}
			return wait
		}
		held = append(held, r)
	}
	return 0
}

type replayCache struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	nextSweep time.Time
}

func newReplayCache() *replayCache {
	return &replayCache{seen: map[string]time.Time{}}
}

// add records a signature until it leaves the timestamp window and reports
// whether it was new.
func (c *replayCache) add(signature string, until, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !now.Before(c.nextSweep) {
		for sig, expires := range c.seen {
			if !now.Before(expires) {
				delete(c.seen, sig)
			}
		}
		c.nextSweep = now.Add(10 * time.Second)
	}
	if expires, ok := c.seen[signature]; ok && now.Before(expires) {
		return false
	}
	c.seen[signature] = until
	return true
}
