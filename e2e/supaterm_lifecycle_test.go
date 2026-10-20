package e2e

import (
	"crypto/ed25519"
	"net/http"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/e2e/supaterm"
)

func TestSupatermRecoversFromARelayRestart(t *testing.T) {
	t.Parallel()
	addr := "RELAY_ADDR=127.0.0.1:" + freePort(t)
	first := startRelay(t, addr)
	h := startSupatermHost(t, first, "restart")
	c := newSupatermClient(t, first, h)
	if env := c.environment(t); env != "restart" {
		t.Fatalf("environment %q", env)
	}
	s := c.session(t)

	first.signal(syscall.SIGTERM)
	waitClosed(t, s)
	if err := first.waitExit(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	waitHost(t, h, "the host to lose its registration", func(h *supaterm.Host) bool { return h.Status() == supaterm.StatusConnecting })

	startRelay(t, addr)
	waitHost(t, h, "the host to register again", func(h *supaterm.Host) bool { return h.Registrations() == 2 })
	c.http.CloseIdleConnections()
	if env := c.environment(t); env != "restart" {
		t.Fatalf("environment %q after restart", env)
	}
	if c.Dials() != 2 {
		t.Fatalf("%d dials, want one per relay", c.Dials())
	}
	c.Close()
	h.Stop()
}

func TestSupatermRecoversFromAHostRestartWithTheSameIdentity(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	identity := newKey(t)
	first := startSupatermHostKey(t, r, identity, "first")
	c := newSupatermClient(t, r, first)
	if env := c.environment(t); env != "first" {
		t.Fatalf("environment %q", env)
	}
	s := c.session(t)

	first.Stop()
	second := startSupatermHostKey(t, r, identity, "second")
	waitClosed(t, s)
	c.http.CloseIdleConnections()
	if env := c.environment(t); env != "second" {
		t.Fatalf("environment %q after host restart", env)
	}
	if second.Sessions() != 1 {
		t.Fatalf("restarted host accepted %d sessions", second.Sessions())
	}
}

func TestSupatermSupersededHostStopsRedialing(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	identity := newKey(t)
	old := startSupatermHostKey(t, r, identity, "old")
	replacement := startSupatermHostKey(t, r, identity, "new")
	superseded := func(h *supaterm.Host) bool { return slices.Contains(h.Statuses(), supaterm.StatusSuperseded) }
	waitHost(t, old, "the old host to be superseded", superseded)
	time.Sleep(100 * time.Millisecond)
	if old.Dials() != 1 || old.Registrations() != 1 {
		t.Fatalf("superseded host redialed: %d dials, statuses %v", old.Dials(), old.Statuses())
	}
	c := newSupatermClient(t, r, replacement)
	if env := c.environment(t); env != "new" {
		t.Fatalf("client reached %q, want the replacement host", env)
	}
	if m := r.metrics(); m["supersededRegistrations"] != 1 || m["activeHosts"] != 1 {
		t.Fatalf("metrics after supersede: %v", m)
	}
}

func TestSupatermOfflineHostsReportHostOffline(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	expectFailure(t, r, supaterm.Address(newKey(t).Public().(ed25519.PublicKey)), supaterm.FailureHostOffline, http.StatusNotFound)

	h := startSupatermHost(t, r, "offline")
	c := newSupatermClient(t, r, h)
	s := c.session(t)
	h.Stop()
	waitClosed(t, s)
	r.waitMetrics("the host to leave", func(m map[string]float64) bool { return m["activeHosts"] == 0 })
	expectFailure(t, r, h.Address(), supaterm.FailureHostOffline, http.StatusNotFound)
}

func TestSupatermClientDisconnectsReleaseTheHostPair(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	h := startSupatermHost(t, r, "disconnects")
	for _, disconnect := range []struct {
		name string
		do   func(*supaterm.Client)
	}{
		{"browser close without status", (*supaterm.Client).Close},
		{"iOS suspend", func(c *supaterm.Client) { c.CloseWith(websocket.CloseGoingAway, "") }},
		{"Android cancel", (*supaterm.Client).Abort},
	} {
		cl, ce := connectSupaterm(t, r, h.Address())
		if ce != nil {
			t.Fatalf("%s: %v", disconnect.name, ce)
		}
		waitHost(t, h, disconnect.name+" pair", func(h *supaterm.Host) bool { return h.Pairs() == 1 })
		disconnect.do(cl)
		waitHost(t, h, disconnect.name+" release", func(h *supaterm.Host) bool { return h.Pairs() == 0 })
		r.waitIdle()
	}
}

func TestSupatermHostStopClosesClientSessions(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	h := startSupatermHost(t, r, "host-stop")
	var sessions []*supaterm.Session
	for range 4 {
		c := newSupatermClient(t, r, h)
		c.environment(t)
		sessions = append(sessions, c.session(t))
	}
	waitHost(t, h, "four pairs", func(h *supaterm.Host) bool { return h.Pairs() == 4 })
	h.Stop()
	for _, s := range sessions {
		waitClosed(t, s)
	}
	r.waitIdle()
}

func TestSupatermIdleSessionsSurviveHeartbeats(t *testing.T) {
	t.Parallel()
	r := startRelay(t, "RELAY_HEARTBEAT_MS=50")
	h := startSupatermHost(t, r, "idle", func(cfg *supaterm.HostConfig) {
		cfg.Heartbeat = 50 * time.Millisecond
		cfg.KeepAlive = 50 * time.Millisecond
	})
	c := newSupatermClient(t, r, h)
	c.environment(t)
	s := c.session(t)
	time.Sleep(time.Second)
	if s.Closed() {
		t.Fatalf("idle tunnel closed: %v", s.Err())
	}
	if h.Registrations() != 1 || h.Dials() != 1 {
		t.Fatalf("host re-registered while idle: %v", h.Statuses())
	}
	if env := c.environment(t); env != "idle" || c.Dials() != 1 {
		t.Fatalf("environment %q after idling, %d dials", env, c.Dials())
	}
}

func TestSupatermTunnelKeepalivesCrossAnIdleRelay(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	h := startSupatermHost(t, r, "keepalive", func(cfg *supaterm.HostConfig) { cfg.KeepAlive = 30 * time.Millisecond })
	cl, ce := connectSupaterm(t, r, h.Address())
	if ce != nil {
		t.Fatal(ce)
	}
	before := r.metrics()["forwardedMessages"]
	time.Sleep(500 * time.Millisecond)
	if cl.Session.Closed() {
		t.Fatalf("tunnel closed: %v", cl.Session.Err())
	}
	if cl.Session.RecordsReceived() == 0 {
		t.Fatal("client received no keepalive from the host")
	}
	if after := r.metrics()["forwardedMessages"]; after <= before {
		t.Fatalf("relay forwarded no keepalives: %v then %v", before, after)
	}
}

func TestSupatermClientsRecoverAfterTheControlSocketDrops(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	h := startSupatermHost(t, r, "control-loss")
	c := newSupatermClient(t, r, h)
	c.environment(t)
	h.DropControl()
	waitHost(t, h, "the host to register again", func(h *supaterm.Host) bool { return h.Registrations() == 2 })
	end := time.Now().Add(deadline)
	for {
		c.http.CloseIdleConnections()
		resp, err := c.http.Get(tunnelOrigin + "/.well-known/supaterm/environment")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(end) {
			t.Fatalf("client did not recover after control loss: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSupatermDrainingRelayRefusesNewClientsAsBusy(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	h := startSupatermHost(t, r, "drain")
	c := newSupatermClient(t, r, h)
	c.environment(t)
	s := c.session(t)
	r.signal(syscall.SIGTERM)
	for end := time.Now().Add(deadline); ; time.Sleep(5 * time.Millisecond) {
		if code, _ := r.get("/healthz"); code == http.StatusServiceUnavailable {
			break
		}
		if time.Now().After(end) {
			t.Fatal("relay did not start draining")
		}
	}
	expectFailure(t, r, h.Address(), supaterm.FailureRelayBusy, http.StatusServiceUnavailable)
	waitClosed(t, s)
	if err := r.waitExit(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	waitHost(t, h, "the host to notice the shutdown", func(h *supaterm.Host) bool { return h.Status() == supaterm.StatusConnecting })
}
