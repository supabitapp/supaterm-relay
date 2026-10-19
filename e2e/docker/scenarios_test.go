//go:build dockere2e

package docker

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func startHosts(t *testing.T, prefix string, n int) []*host {
	t.Helper()
	hosts := make([]*host, n)
	for i := range hosts {
		hosts[i] = newHost(t, fmt.Sprintf("%s%d", prefix, i))
		hosts[i].waitRegistered(t, 10*time.Second)
	}
	return hosts
}

func waitReregistered(t *testing.T, hosts []*host, minRegs int, since time.Time, within time.Duration) durations {
	t.Helper()
	var took durations
	for _, h := range hosts {
		for h.registrations() < minRegs || !h.isOnline() {
			if time.Since(since) > within {
				t.Fatalf("host %s not re-registered within %s: regs=%d attempts=%d reasons=%v", h.tag, within, h.registrations(), h.attemptCount(), h.reasons())
			}
			time.Sleep(20 * time.Millisecond)
		}
		at, _ := h.registeredAt(minRegs)
		took = append(took, at.Sub(since))
	}
	return took
}

func allReachable(t *testing.T, hosts []*host, label string, within time.Duration) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, len(hosts))
	for _, h := range hosts {
		wg.Go(func() {
			if _, err := exchangeWithRetry(st.base, h, label+"-"+h.tag, 4, within); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func gapsOf(hosts []*host) durations {
	var d durations
	for _, h := range hosts {
		d = append(d, h.reconnectGaps()...)
	}
	return d
}

func acceptFailures(hosts []*host) (int64, []string) {
	var n int64
	var reasons []string
	for _, h := range hosts {
		if f := h.acceptFails.Load(); f > 0 {
			n += f
			reasons = append(reasons, h.reasons()...)
		}
	}
	return n, reasons
}

func TestPublicSurface(t *testing.T) {
	st.baseline(t)
	for _, path := range []string{"/", "/healthz", "/metrics/", "/v1/directory", "/v1/control/../healthz", "/debug/pprof/", "/v1/accept/"} {
		if code := httpStatus(t, "GET", st.http+path, nil); code != 404 {
			t.Fatalf("public %s: %d", path, code)
		}
	}
	if code := httpStatus(t, "GET", st.http+"/metrics", nil); code != http.StatusOK {
		t.Fatalf("public metrics: %d", code)
	}
	if code := httpStatus(t, "POST", st.http+"/metrics", nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST metrics: %d", code)
	}
	if code := httpStatus(t, "POST", st.http+"/v1/control", nil); code != 405 {
		t.Fatalf("POST control: %d", code)
	}
	results := map[string]string{}
	for _, target := range []string{
		"http://10.231.2.10:9090/healthz",
		"http://relay:9090/metrics",
	} {
		r := st.probe(t, "-mode", "http", "-url", target)
		if r.Error == "" {
			t.Fatalf("internal endpoint %s reachable from the public network: %d", target, r.Status)
		}
		results[target] = r.Error
	}
	if r := st.probe(t, "-mode", "http", "-url", "http://relay:8080/healthz"); r.Status != 404 {
		t.Fatalf("relay public healthz from public network: %+v", r)
	}
	st.record("publicSurface", results)
}

func TestPairingOnRelay(t *testing.T) {
	st.baseline(t)
	hosts := startHosts(t, "pair", 12)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	var messages atomic.Int64
	start := time.Now()
	for _, h := range hosts {
		for c := range 3 {
			wg.Go(func() {
				ws, code, err := connect(st.base, h.id)
				if err != nil {
					errs <- fmt.Errorf("connect %s: %d %v", h.tag, code, err)
					return
				}
				defer ws.Close()
				if err := exchange(ws, h, fmt.Sprintf("%s-c%d", h.tag, c), 60); err != nil {
					errs <- err
					return
				}
				messages.Add(120)
			})
		}
		wg.Go(func() {
			ws, code, err := connect(st.base, h.id)
			if err != nil {
				errs <- fmt.Errorf("connect %s: %d %v", h.tag, code, err)
				return
			}
			defer ws.Close()
			if err := stream(ws, h, h.tag+"-stream", 1000); err != nil {
				errs <- err
				return
			}
			messages.Add(2000)
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if m := st.metrics(t); m["activeHosts"] != 12 {
		t.Fatalf("activeHosts %v", m["activeHosts"])
	}

	if f, reasons := acceptFailures(hosts); f > 0 {
		t.Fatalf("%d accept failures: %v", f, reasons)
	}
	st.record("pairing", map[string]any{"messagesVerified": messages.Load(), "seconds": time.Since(start).Seconds()})
}

func TestDuplicateIdentityNewestWins(t *testing.T) {
	st.baseline(t)
	first := newHost(t, "dup-old")
	first.waitRegistered(t, 10*time.Second)
	if _, err := exchangeWithRetry(st.base, first, "before", 2, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	second := startHostKey(t, "dup-new", first.priv)
	second.waitRegistered(t, 10*time.Second)
	select {
	case <-first.done:
	case <-time.After(10 * time.Second):
		t.Fatal("older registration was not superseded")
	}
	if codes := first.codes(); len(codes) != 1 || codes[0] != supersededCode {
		t.Fatalf("older registration closed with %v, want [%d]", codes, supersededCode)
	}
	for i := range 5 {
		if _, err := exchangeWithRetry(st.base, second, fmt.Sprintf("after-%d", i), 3, 5*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	m := st.waitMetrics(t, "supersede counted", 5*time.Second, func(m map[string]float64) bool { return m["supersededRegistrations"] >= 1 })
	st.record("duplicateIdentity", map[string]any{"supersededRegistrations": m["supersededRegistrations"]})
}

func TestRelayRestart(t *testing.T) {
	st.baseline(t)
	hosts := startHosts(t, "rr", 9)

	start := time.Now()
	st.must(t, "restart", "relay")
	graceful := waitReregistered(t, hosts, 2, start, 30*time.Second)
	allReachable(t, hosts, "after-restart", 10*time.Second)

	start = time.Now()
	st.must(t, "kill", "-s", "SIGKILL", "relay")
	st.must(t, "up", "-d", "relay")
	abrupt := waitReregistered(t, hosts, 3, start, 30*time.Second)
	allReachable(t, hosts, "after-kill", 10*time.Second)
	st.record("relayRestart", map[string]any{
		"gracefulRestartReregisteredSinceCommand": graceful.summary(),
		"sigkillReregisteredSinceCommand":         abrupt.summary(),
		"reconnectGaps":                           gapsOf(hosts).summary(),
	})
}

func TestRateLimitingRejectsSpoofedHeaders(t *testing.T) {
	t.Cleanup(func() {
		if err := st.collectLogs(); err != nil {
			t.Error(err)
		}
		st.setEnv(map[string]string{"E2E_RELAY_RATE": ""})
		_, _ = st.compose("up", "-d", "--wait", "relay")
	})
	st.setEnv(map[string]string{"E2E_RELAY_RATE": "5"})
	st.baseline(t)
	spoof := http.Header{"X-Forwarded-For": {probeIP}, "X-Real-Ip": {probeIP}, "Forwarded": {"for=" + probeIP}}
	started := time.Now()
	var codes []int
	for range 40 {
		codes = append(codes, dialCode(st.base+"/v1/control?publicKey="+randomKey(), spoof))
	}
	admitted := countOf(codes, 101)
	if codes[len(codes)-1] != 429 || countOf(codes, 429) == 0 || float64(admitted) > 5+5*time.Since(started).Seconds()+1 {
		t.Fatalf("relay limiter not enforced per client: %v", codes)
	}
	result := st.probe(t, "-mode", "connect", "-url", "ws://relay:8080", "-n", "3", "-xff", probeIP)
	if countOf(result.Codes, 404) != 3 {
		t.Fatalf("spoofed headers consumed another client's budget: %v", result.Codes)
	}
	st.record("rateLimiting", map[string]any{"hostCodes": codes, "probeCodes": result.Codes})
}
