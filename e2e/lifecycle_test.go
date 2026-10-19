package e2e

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/internal/endpoint"
)

func TestAdmissionRateLimit(t *testing.T) {
	r := startRelay(t, "RELAY_ADMISSION_RATE=5")
	unknown := endpoint.EndpointID(randomBytes(32))
	var codes []int
	for range 20 {
		_, resp, err := endpoint.Connect(r.base, unknown)
		if err == nil || resp == nil {
			t.Fatalf("unexpected connect result %v", err)
		}
		codes = append(codes, resp.StatusCode)
	}
	if codes[0] != 404 || codes[len(codes)-1] != 429 {
		t.Fatalf("unexpected status sequence %v", codes)
	}
	if code, _ := r.get("/healthz"); code != 200 {
		t.Fatalf("healthz rate limited: %d", code)
	}
}

func TestHeartbeatCleanup(t *testing.T) {
	r := startRelay(t, "RELAY_HEARTBEAT_MS=100")
	h := register(t, r)

	healthyClient, healthyHost, _ := pairUp(t, r, h)
	pings := make(chan struct{}, 64)
	healthyClient.SetPingHandler(func(data string) error {
		select {
		case pings <- struct{}{}:
		default:
		}
		return healthyClient.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
	})
	echoed := make(chan message, 1)
	go func() {
		for {
			typ, data, err := healthyClient.ReadMessage()
			if err != nil {
				return
			}
			echoed <- message{typ, data}
		}
	}()
	go func() {
		for {
			typ, data, err := healthyHost.ReadMessage()
			if err != nil || healthyHost.WriteMessage(typ, data) != nil {
				return
			}
		}
	}()

	_, deadHost, deadID := pairUp(t, r, h)
	ce := expectClose(t, deadHost, websocket.CloseGoingAway)
	if ce.Text != "peer timeout" {
		t.Fatalf("unexpected reason %q", ce.Text)
	}
	if ev := nextEvent(t, h, "closed"); ev.ConnectionID != deadID {
		t.Fatalf("closed event mismatch %+v", ev)
	}

	for range 6 {
		select {
		case <-pings:
		case <-time.After(deadline):
			t.Fatal("no relay ping")
		}
	}
	want := []byte("alive after heartbeats")
	send(t, healthyClient, message{websocket.TextMessage, want})
	select {
	case got := <-echoed:
		if string(got.data) != string(want) {
			t.Fatalf("echo mismatch %q", got.data)
		}
	case <-time.After(deadline):
		t.Fatal("healthy pair stopped forwarding")
	}
	if m := r.metrics(); m["activePairs"] != 1 || m["activeHosts"] != 1 {
		t.Fatalf("unexpected metrics %v", m)
	}
}

func TestAbruptDisconnects(t *testing.T) {
	r := startRelay(t)
	h := register(t, r)

	client, host, id := pairUp(t, r, h)
	client.UnderlyingConn().Close()
	ce := expectClose(t, host, websocket.CloseGoingAway)
	if ce.Text != "peer disconnected" {
		t.Fatalf("unexpected reason %q", ce.Text)
	}
	if ev := nextEvent(t, h, "closed"); ev.ConnectionID != id {
		t.Fatalf("closed mismatch %+v", ev)
	}

	client2, host2, id2 := pairUp(t, r, h)
	host2.UnderlyingConn().Close()
	expectClose(t, client2, websocket.CloseGoingAway)
	if ev := nextEvent(t, h, "closed"); ev.ConnectionID != id2 {
		t.Fatalf("closed mismatch %+v", ev)
	}

	_, ev3 := connect(t, r, h)
	if ev3.ConnectionID == id || ev3.ConnectionID == id2 {
		t.Fatal("connection id reused")
	}
	r.waitMetrics("pairs released", func(m map[string]float64) bool { return m["activePairs"] == 0 && m["pendingPairs"] == 1 })
}

func TestCloseCodesPreserved(t *testing.T) {
	r := startRelay(t)
	h := register(t, r)
	cases := []struct {
		fromClient bool
		frame      []byte
		code       int
		reason     string
	}{
		{true, websocket.FormatCloseMessage(4001, "bye now"), 4001, "bye now"},
		{false, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done"), websocket.CloseNormalClosure, "done"},
		{true, websocket.FormatCloseMessage(websocket.CloseGoingAway, "tab closed"), websocket.CloseGoingAway, "tab closed"},
		{false, websocket.FormatCloseMessage(3000, ""), 3000, ""},
		{true, []byte{}, websocket.CloseNormalClosure, ""},
	}
	for _, c := range cases {
		client, host, _ := pairUp(t, r, h)
		from, to := client, host
		if !c.fromClient {
			from, to = host, client
		}
		if err := from.WriteControl(websocket.CloseMessage, c.frame, time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		ce := expectClose(t, to, c.code)
		if ce.Text != c.reason {
			t.Fatalf("reason %q, want %q", ce.Text, c.reason)
		}
		nextEvent(t, h, "closed")
	}
}

func TestControlCloseClosesAllPairs(t *testing.T) {
	r := startRelay(t)
	h := register(t, r)
	c1, s1, _ := pairUp(t, r, h)
	c2, s2, _ := pairUp(t, r, h)
	c3, _ := connect(t, r, h)
	if err := h.Control.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, ws := range []*websocket.Conn{c1, s1, c2, s2, c3} {
		ce := expectClose(t, ws, websocket.CloseGoingAway)
		if ce.Text != "host offline" {
			t.Fatalf("unexpected reason %q", ce.Text)
		}
	}
	r.waitMetrics("all released", func(m map[string]float64) bool {
		return m["activeHosts"] == 0 && m["activePairs"] == 0 && m["pendingPairs"] == 0 && m["openSockets"] == 0
	})
}

func TestHostRemovalClosesStalledPairsTogether(t *testing.T) {
	r := startRelay(t, "RELAY_MAX_MESSAGE_BYTES=65536", "RELAY_DELIVERY_TIMEOUT_MS=30000")
	baseline := r.metrics()
	const count = 8
	block := make([]byte, 65536)
	for round := range 3 {
		h := register(t, r)
		healthy := make([]*websocket.Conn, 0, count)
		ready := make(chan struct{}, count)
		var producers sync.WaitGroup
		for range count {
			_, host, _ := pairUp(t, r, h)
			healthy = append(healthy, host)
			producers.Go(func() {
				for n := 0; ; n++ {
					if n == 9 {
						ready <- struct{}{}
					}
					_ = host.SetWriteDeadline(time.Now().Add(deadline))
					if host.WriteMessage(websocket.BinaryMessage, block) != nil {
						return
					}
				}
			})
			// The destination does not consume data. Its TCP window eventually
			// blocks the relay writer while the opposite peer can still read.
		}
		for range count {
			select {
			case <-ready:
			case <-time.After(deadline):
				t.Fatal("producers did not fill destination windows")
			}
		}
		started := time.Now()
		h.Close()
		for _, host := range healthy {
			expectClose(t, host, websocket.CloseGoingAway)
		}
		r.waitMetrics("stalled host released all resources", func(m map[string]float64) bool {
			return m["activeHosts"] == 0 && m["activePairs"] == 0 && m["clientSlots"] == 0 && m["openSockets"] == 0
		})
		if elapsed := time.Since(started); elapsed > 3*time.Second {
			t.Fatalf("round %d: teardown of %d blocked pairs took %s", round, count, elapsed)
		}
		producers.Wait()
		r.waitMetrics("stalled handlers and heartbeats exited", func(m map[string]float64) bool {
			return m["goroutines"] <= baseline["goroutines"]+3
		})
	}
	if growth := r.metrics()["heapAllocBytes"] - baseline["heapAllocBytes"]; growth > 8<<20 {
		t.Fatalf("repeated stalled teardown retained %.0f bytes", growth)
	}
}

func TestGracefulShutdownWaitsForActivePairs(t *testing.T) {
	r := startRelay(t)
	h := register(t, r)
	client, host, _ := pairUp(t, r, h)

	r.signal(syscall.SIGTERM)
	waitHealth(t, r, 503)
	_, resp, err := endpoint.Connect(r.base, h.ID)
	expectStatus(t, resp, err, 503)
	_, _, resp, err = endpoint.DialControl(r.base, endpoint.B64(randomBytes(32)))
	expectStatus(t, resp, err, 503)

	for i := range 10 {
		m := message{websocket.BinaryMessage, []byte{byte(i)}}
		send(t, client, m)
		expectMessage(t, host, m)
		send(t, host, m)
		expectMessage(t, client, m)
	}
	start := time.Now()
	if err := client.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "finished"), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	expectClose(t, host, websocket.CloseNormalClosure)
	if err := r.waitExit(deadline); err != nil {
		t.Fatalf("relay exit: %v\n%s", err, r.stderr)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("relay waited %s after last pair finished", elapsed)
	}
}

func TestGracefulShutdownExitsWithinBudget(t *testing.T) {
	r := startRelay(t, "RELAY_PAIR_TIMEOUT_MS=60000")
	h := register(t, r)
	var readers []*websocket.Conn
	for range 3 {
		client, host, _ := pairUp(t, r, h)
		readers = append(readers, client, host)
	}
	pairUp(t, r, h)
	pending, _ := connect(t, r, h)
	readers = append(readers, pending)
	r.waitMetrics("pairs established", func(m map[string]float64) bool { return m["activePairs"] == 4 && m["pendingPairs"] == 1 })

	results := make(chan error, len(readers)+1)
	for _, ws := range readers {
		go func() {
			ce, err := readClose(ws)
			if err == nil && ce.Code != websocket.CloseGoingAway {
				err = fmt.Errorf("close %d %q", ce.Code, ce.Text)
			}
			results <- err
		}()
	}
	go func() {
		<-h.Done
		var ce *websocket.CloseError
		if !errors.As(h.Err, &ce) || ce.Code != websocket.CloseGoingAway {
			results <- fmt.Errorf("control: %v", h.Err)
			return
		}
		results <- nil
	}()

	start := time.Now()
	r.signal(syscall.SIGTERM)
	if err := r.waitExit(8 * time.Second); err != nil {
		t.Fatalf("relay exit: %v\n%s", err, r.stderr)
	}
	elapsed := time.Since(start)
	if elapsed < 4*time.Second || elapsed > 5*time.Second+250*time.Millisecond {
		t.Fatalf("shutdown took %s, want within the 5s budget\n%s", elapsed, r.stderr)
	}
	for range len(readers) + 1 {
		if err := <-results; err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "connection reset") {
			t.Fatalf("socket not closed cleanly: %v", err)
		}
	}
	if !strings.Contains(r.stderr.String(), "5 pairs force-closed") {
		t.Fatalf("unexpected drain log:\n%s", r.stderr)
	}
	t.Logf("shutdown with 4 active pairs, 1 pending pair, and a non-reading peer took %s", elapsed.Round(time.Millisecond))
}

func waitHealth(t *testing.T, r *relay, want int) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		resp, err := http.Get("http://" + r.adminAddr() + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == want {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("healthz never returned %d", want)
}

func TestInvalidConfigExits(t *testing.T) {
	cmd := exec.Command(relayBin)
	cmd.Env = append(os.Environ(), "RELAY_ADDR=127.0.0.1:0", "RELAY_MAX_CLIENTS_PER_HOST=zero")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(out), "RELAY_MAX_CLIENTS_PER_HOST") {
		t.Fatalf("expected exit 2 naming RELAY_MAX_CLIENTS_PER_HOST, got %v: %s", err, out)
	}
}

func TestUnknownCommandsExitWithoutServing(t *testing.T) {
	for _, args := range [][]string{{"trace-tag", strings.Repeat("ab", 32)}, {"metrics", "extra"}} {
		ctx, cancel := context.WithTimeout(t.Context(), deadline)
		cmd := exec.CommandContext(ctx, relayBin, args...)
		cmd.Env = append(os.Environ(), "RELAY_ADDR=127.0.0.1:0")
		out, err := cmd.CombinedOutput()
		cancel()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(out), "usage:") {
			t.Fatalf("%v: expected exit 2 with usage, got %v: %s", args, err, out)
		}
	}
}

func TestAuthenticationCannotRegisterDuringShutdown(t *testing.T) {
	r := startRelay(t)
	h := register(t, r)
	client, accepted, _ := pairUp(t, r, h)
	key := newKey(t)
	ws, challenge, _, err := endpoint.DialControl(r.base, endpoint.B64(key.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	r.signal(syscall.SIGTERM)
	waitHealth(t, r, http.StatusServiceUnavailable)
	if err := ws.WriteJSON(map[string]string{"type": "authenticate", "signature": endpoint.SignChallenge(key, endpoint.EndpointID(key.Public().(ed25519.PublicKey)), challenge.Nonce)}); err != nil {
		t.Fatal(err)
	}
	_ = ws.SetReadDeadline(time.Now().Add(deadline))
	_, _, err = ws.ReadMessage()
	var closed *websocket.CloseError
	if !errors.As(err, &closed) || closed.Code != websocket.CloseGoingAway {
		t.Fatalf("authentication completed during shutdown: %v", err)
	}
	client.Close()
	accepted.Close()
	if err := r.waitExit(8 * time.Second); err != nil {
		t.Fatal(err)
	}
}
