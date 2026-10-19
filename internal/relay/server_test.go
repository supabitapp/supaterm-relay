package relay

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/internal/dashboard"
)

type logCapture struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func captureLogs(t *testing.T) *logCapture {
	t.Helper()
	logs := &logCapture{}
	previous := log.Writer()
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	return logs
}

func TestHandlerPanicsAreLoggedWithoutThePeer(t *testing.T) {
	logs := captureLogs(t)
	server := newHTTPServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panicFor(netip.MustParseAddr("203.0.113.77"))
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(ln) }()
	t.Cleanup(func() { _ = server.Close() })
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: relay\r\n\r\n")
	_, _ = io.ReadAll(conn)
	out := logs.String()
	if !strings.Contains(out, "relay: panic: handler failed") || !strings.Contains(out, "relay.panicFor") {
		t.Fatalf("panic log should name the panic and its frames:\n%s", out)
	}
	for _, leak := range []string{conn.LocalAddr().String(), "panicFor("} {
		if strings.Contains(out, leak) {
			t.Fatalf("panic log exposed the peer or frame arguments (%s):\n%s", leak, out)
		}
	}
}

func TestSocketPanicsAreLoggedWithoutThePeer(t *testing.T) {
	logs := captureLogs(t)
	s := New(Config{AdmissionRate: 100, MaxConnectionsPerIP: 1})
	handler := s.admit(false, func(http.ResponseWriter, *http.Request) func() {
		return func() { panicFor(netip.MustParseAddr("203.0.113.77")) }
	})
	r := httptest.NewRequest(http.MethodGet, "/v1/connect", nil)
	handler(httptest.NewRecorder(), r)
	waitForOpenConnections(t, s, 0, "socket exit")
	out := logs.String()
	if !strings.Contains(out, "relay: panic: handler failed") || !strings.Contains(out, "relay.panicFor") {
		t.Fatalf("panic log should name the panic and its frames:\n%s", out)
	}
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	for _, leak := range []string{peer, "panicFor("} {
		if strings.Contains(out, leak) {
			t.Fatalf("panic log exposed the peer or frame arguments (%s):\n%s", leak, out)
		}
	}
}

func TestAbortedHandlersAndSocketsAreNotLogged(t *testing.T) {
	logs := captureLogs(t)
	server := httptest.NewServer(logPanicsWithoutPeer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	})))
	t.Cleanup(server.Close)
	if resp, err := http.Get(server.URL); err == nil {
		resp.Body.Close()
	}
	s := New(Config{AdmissionRate: 100, MaxConnectionsPerIP: 1})
	s.admit(false, func(http.ResponseWriter, *http.Request) func() {
		return func() { panic(http.ErrAbortHandler) }
	})(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/connect", nil))
	waitForOpenConnections(t, s, 0, "socket exit")
	if out := logs.String(); out != "" {
		t.Fatalf("aborted requests should not be logged:\n%s", out)
	}
}

//go:noinline
func panicFor(addr netip.Addr) {
	if addr.IsValid() {
		panic("handler failed")
	}
}

func TestCloseNowPongsCannotExtendDrain(t *testing.T) {
	server := New(Config{Heartbeat: time.Second})
	finished := make(chan time.Duration, 1)
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, ok := server.upgrade(w, r, 1024)
		if !ok {
			return
		}
		server.newPeer(ws, nil, nil)
		start := time.Now()
		server.closeNow(ws, closeMsg{websocket.CloseGoingAway, "closing"})
		finished <- time.Since(start)
	}))
	defer listener.Close()
	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(listener.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetCloseHandler(func(int, string) error { return nil })
	go func() {
		for {
			if _, _, err := client.ReadMessage(); err != nil {
				return
			}
		}
	}()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case elapsed := <-finished:
			if elapsed > 2*time.Second {
				t.Fatalf("pongs extended close drain to %s", elapsed)
			}
			return
		case <-ticker.C:
			_ = client.WriteControl(websocket.PongMessage, nil, time.Now().Add(time.Second))
		case <-timeout.C:
			t.Fatal("pongs kept the close drain alive")
		}
	}
}

func TestPublicListenerServesDashboardAndMetrics(t *testing.T) {
	cfg, err := LoadConfig(env(map[string]string{"RELAY_PRIVATE_ADDR": "127.0.0.1:0"}))
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg)
	serve := func(path string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		s.http.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		return response
	}
	if response := serve("/dashboard"); response.Code/100 != 3 || response.Header().Get("Location") != "/dashboard/" {
		t.Errorf("/dashboard: status %d location %q", response.Code, response.Header().Get("Location"))
	}
	for path, status := range map[string]int{
		"/dashboard/":       http.StatusOK,
		"/dashboard/stats":  http.StatusOK,
		"/dashboard/static": http.StatusNotFound,
		"/metrics":          http.StatusOK,
	} {
		if response := serve(path); response.Code != status {
			t.Errorf("%s: status %d", path, response.Code)
		}
	}
}

func TestMetricsIncludeBatchBufferCapacity(t *testing.T) {
	s := New(Config{})
	response := httptest.NewRecorder()
	s.handleMetrics(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	var metrics struct{ DataBufferBytesPerSocket int }
	if err := json.Unmarshal(response.Body.Bytes(), &metrics); err != nil {
		t.Fatal(err)
	}
	want := s.upgrader.ReadBufferSize + readBatchSize + s.upgrader.WriteBufferSize + batchBufferSize
	if metrics.DataBufferBytesPerSocket != want {
		t.Fatalf("buffer capacity = %d, want %d", metrics.DataBufferBytesPerSocket, want)
	}
}

func TestDashboardStatsMatchMetrics(t *testing.T) {
	cfg, err := LoadConfig(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg)
	listener := httptest.NewServer(s.http.Handler)
	defer listener.Close()
	openPair(t, registerHost(t, "ws"+strings.TrimPrefix(listener.URL, "http")))
	offline, err := http.Get(listener.URL + "/v1/connect?endpointId=" + strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	offline.Body.Close()
	response := httptest.NewRecorder()
	s.handleMetrics(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	var want dashboard.Stats
	if err := json.Unmarshal(response.Body.Bytes(), &want); err != nil {
		t.Fatal(err)
	}
	if got := s.dashboardStats(); !reflect.DeepEqual(got, want) || got.ActiveHosts != 1 || got.ActivePairs != 1 || got.RejectedConnections != 1 {
		t.Fatalf("dashboard stats = %+v, want %+v", got, want)
	}
}
