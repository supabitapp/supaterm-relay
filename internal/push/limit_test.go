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

func TestTakeReturnsWindowEventsWhenAnotherQuotaRefuses(t *testing.T) {
	now := testEpoch
	w, tight := newWindow(2, time.Hour), newLimiter(1, time.Hour, 1)
	take(now, quota{tight, "a"})
	for range 5 {
		if take(now, quota{w, "a"}, quota{tight, "a"}) == 0 {
			t.Fatal("exhausted limiter admitted")
		}
	}
	for i := range 2 {
		if wait := take(now, quota{w, "a"}); wait != 0 {
			t.Fatalf("window take %d after refused takes waited %s", i, wait)
		}
	}
}

func TestWindowCapsEveryRollingPeriod(t *testing.T) {
	w := newWindow(5, time.Hour)
	now := testEpoch
	for i := range 5 {
		if take(now.Add(time.Duration(i)*time.Minute), quota{w, "token"}) != 0 {
			t.Fatalf("event %d was limited", i)
		}
	}
	if wait := take(now.Add(59*time.Minute), quota{w, "token"}); wait != time.Minute {
		t.Fatalf("sixth event in the hour waited %s, want 1m", wait)
	}
	if take(now.Add(time.Hour), quota{w, "token"}) != 0 {
		t.Fatal("event after the first left the hour was limited")
	}
	if wait := take(now.Add(time.Hour+30*time.Second), quota{w, "token"}); wait != 30*time.Second {
		t.Fatalf("event before the second left the hour waited %s", wait)
	}
	if take(now.Add(time.Hour), quota{w, "other"}) != 0 {
		t.Fatal("unrelated key was limited")
	}
	if take(now.Add(3*time.Hour), quota{w, "fresh"}) != 0 || len(w.entries) != 1 {
		t.Fatalf("idle keys were kept: %d entries", len(w.entries))
	}
}

func TestReplayCache(t *testing.T) {
	c := newReplayCache(maxReplayEntries)
	now := testEpoch
	sig := signature{1}
	if ok, _ := c.add(sig, now.Add(time.Minute), now); !ok {
		t.Fatal("first use was refused")
	}
	if ok, _ := c.add(sig, now.Add(time.Minute), now.Add(59*time.Second)); ok {
		t.Fatal("replay within the window was accepted")
	}
	if ok, _ := c.add(sig, now.Add(2*time.Minute), now.Add(time.Minute)); !ok {
		t.Fatal("signature outside its window stayed blocked")
	}
	c.add(signature{2}, now, now)
	c.add(signature{3}, now.Add(time.Hour), now.Add(time.Hour))
	if _, ok := c.seen[signature{2}]; ok {
		t.Fatal("expired signature was not swept")
	}
}

func TestReplayCacheRefusesNewSignaturesWhenFull(t *testing.T) {
	c := newReplayCache(2)
	now := testEpoch
	c.add(signature{1}, now.Add(time.Minute), now)
	c.add(signature{2}, now.Add(time.Minute), now)
	if ok, wait := c.add(signature{3}, now.Add(time.Minute), now); ok || wait != replaySweep {
		t.Fatalf("full cache answered %v %s", ok, wait)
	}
	if ok, wait := c.add(signature{1}, now.Add(time.Minute), now.Add(time.Second)); ok || wait != 0 {
		t.Fatalf("replay into a full cache answered %v %s", ok, wait)
	}
	if ok, _ := c.add(signature{3}, now.Add(2*time.Minute), now.Add(time.Minute)); !ok {
		t.Fatal("cache stayed full after its signatures expired")
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
	if retry, _ := strconv.Atoi(w.Header().Get("Retry-After")); retry != 3600 {
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

	g.advance(59 * time.Minute)
	expect(t, enroll(token(21), "192.0.2.1:1000", ""), http.StatusTooManyRequests, "rate_limited")
	expect(t, enroll(token(1), "192.0.2.3:1000", ""), http.StatusTooManyRequests, "rate_limited")
	g.advance(time.Minute)
	if w := enroll(token(21), "192.0.2.1:1000", ""); w.Code != http.StatusCreated {
		t.Fatalf("enrollment after the hour: %d", w.Code)
	}
}

func TestHandleChangeRateLimitPerInstallation(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	in := g.enroll(token(1))
	var handles []string
	for range 10 {
		handles = append(handles, g.mint(in, host))
	}
	w := g.call(http.MethodPost, "/v1/installations/"+in.InstallationID+"/handles", in.OwnerToken,
		map[string]string{"hostKey": b64u.EncodeToString(make([]byte, 32))})
	expect(t, w, http.StatusTooManyRequests, "rate_limited")
	if retry, _ := strconv.Atoi(w.Header().Get("Retry-After")); retry != 120 {
		t.Fatalf("Retry-After = %q", w.Header().Get("Retry-After"))
	}
	path := "/v1/handles/" + handles[0]
	expect(t, g.serve(g.signed(host, http.MethodDelete, path, nil, g.now)), http.StatusTooManyRequests, "rate_limited")
	g.mint(g.enroll(token(2)), host)

	g.advance(2 * time.Minute)
	if w := g.serve(g.signed(host, http.MethodDelete, path, nil, g.now)); w.Code != http.StatusNoContent {
		t.Fatalf("host delete after refill: %d %s", w.Code, w.Body)
	}
}

func TestHandleChangeRateLimitPerNetwork(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	for i := range 3 {
		in := g.enroll(token(byte(i + 1)))
		for range 10 {
			g.mint(in, host)
		}
	}
	in := g.enroll(token(4))
	expect(t, g.call(http.MethodPost, "/v1/installations/"+in.InstallationID+"/handles", in.OwnerToken,
		map[string]string{"hostKey": b64u.EncodeToString(make([]byte, 32))}), http.StatusTooManyRequests, "rate_limited")
}
