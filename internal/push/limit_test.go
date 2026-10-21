package push

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTakeConsumesAllQuotasOrNone(t *testing.T) {
	now := testEpoch
	roomy, tight := newLimiter(10, time.Minute, 10), newLimiter(1, time.Minute, 1)
	if wait := take(now, quota{roomy, "a"}, quota{tight, "a"}); wait != 0 {
		t.Fatalf("first take waited %s", wait)
	}
	for range 20 {
		if wait := take(now, quota{roomy, "a"}, quota{tight, "a"}); wait <= 0 || wait > time.Minute {
			t.Fatalf("exhausted take waited %s", wait)
		}
	}
	for i := range 9 {
		if wait := take(now, quota{roomy, "a"}); wait != 0 {
			t.Fatalf("take %d after refused takes waited %s", i, wait)
		}
	}
}

func TestLimiterForgetsOnlyRefilledBuckets(t *testing.T) {
	l := newLimiter(5, time.Hour, 5)
	now := testEpoch
	for range 5 {
		take(now, quota{l, "token"})
	}
	if take(now.Add(time.Minute), quota{l, "other"}) != 0 {
		t.Fatal("unrelated key was limited")
	}
	if take(now.Add(time.Minute), quota{l, "token"}) == 0 {
		t.Fatal("bucket was forgotten before it refilled")
	}
	if take(now.Add(62*time.Minute), quota{l, "other"}) != 0 || len(l.entries) != 1 {
		t.Fatalf("refilled buckets were kept: %d entries", len(l.entries))
	}
}

func TestReplayCache(t *testing.T) {
	c := newReplayCache()
	now := testEpoch
	if !c.add("sig", now.Add(time.Minute), now) || c.add("sig", now.Add(time.Minute), now.Add(59*time.Second)) {
		t.Fatal("replay within the window was accepted")
	}
	if !c.add("sig", now.Add(2*time.Minute), now.Add(time.Minute)) {
		t.Fatal("signature outside its window stayed blocked")
	}
	c.add("old", now, now)
	c.add("new", now.Add(time.Hour), now.Add(time.Hour))
	if _, ok := c.seen["old"]; ok {
		t.Fatal("expired signature was not swept")
	}
}

func TestSendRateLimitPerHandle(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	in := g.enroll(token(1))
	handle, other := g.mint(in, host), g.mint(in, host)
	for i := range 10 {
		if w := g.send(host, handle); w.Code != http.StatusOK {
			t.Fatalf("send %d: %d %s", i, w.Code, w.Body)
		}
		g.advance(time.Millisecond)
	}
	w := g.send(host, handle)
	expect(t, w, http.StatusTooManyRequests, "rate_limited")
	if retry, _ := strconv.Atoi(w.Header().Get("Retry-After")); retry != 2 {
		t.Fatalf("Retry-After = %q", w.Header().Get("Retry-After"))
	}
	if w := g.send(host, other); w.Code != http.StatusOK {
		t.Fatalf("another handle was limited: %d", w.Code)
	}
	g.advance(2 * time.Second)
	if w := g.send(host, handle); w.Code != http.StatusOK {
		t.Fatalf("send after refill: %d", w.Code)
	}
}

func TestSendRateLimitPerInstallation(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	in := g.enroll(token(1))
	var handles []string
	for range 3 {
		handles = append(handles, g.mint(in, host))
	}
	sent := 0
	for i := range 30 {
		w := g.send(host, handles[i%len(handles)])
		g.advance(time.Millisecond)
		if w.Code == http.StatusTooManyRequests {
			break
		}
		sent++
	}
	if sent != 20 {
		t.Fatalf("installation burst allowed %d sends, want 20", sent)
	}
}

func TestEnrollmentRateLimits(t *testing.T) {
	g := newGateway(t)
	enroll := func(tok, remote, forwarded string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/enrollments",
			strings.NewReader(`{"token":"`+tok+`","topic":"`+testTopic+`","environment":"sandbox"}`))
		r.RemoteAddr = remote
		if forwarded != "" {
			r.Header.Set("X-Forwarded-For", forwarded)
		}
		return g.serve(r)
	}
	for i := range 5 {
		if w := enroll(token(1), "192.0.2.1:1000", ""); w.Code != http.StatusCreated {
			t.Fatalf("challenge %d: %d", i, w.Code)
		}
	}
	w := enroll(token(1), "192.0.2.2:1000", "")
	expect(t, w, http.StatusTooManyRequests, "rate_limited")
	if retry, _ := strconv.Atoi(w.Header().Get("Retry-After")); retry != 720 {
		t.Fatalf("Retry-After = %q", w.Header().Get("Retry-After"))
	}

	for i := range 15 {
		if w := enroll(token(byte(i+2)), "192.0.2.1:1000", ""); w.Code != http.StatusCreated {
			t.Fatalf("enrollment %d: %d", i, w.Code)
		}
	}
	expect(t, enroll(token(20), "192.0.2.1:1000", ""), http.StatusTooManyRequests, "rate_limited")
	expect(t, enroll(token(20), "127.0.0.1:1000", "192.0.2.1"), http.StatusTooManyRequests, "rate_limited")
	if w := enroll(token(20), "192.0.2.1:1000", "203.0.113.9"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("a non-loopback peer chose its client IP: %d", w.Code)
	}
	if w := enroll(token(20), "127.0.0.1:1000", "203.0.113.9"); w.Code != http.StatusCreated {
		t.Fatalf("enrollment from another forwarded network: %d", w.Code)
	}
}
