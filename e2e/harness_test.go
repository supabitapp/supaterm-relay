package e2e

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/internal/endpoint"
)

const deadline = 5 * time.Second

var relayBin, probeBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "supaterm-relay-e2e")
	if err != nil {
		panic(err)
	}
	build := func(name, pkg string) string {
		out := filepath.Join(dir, name)
		args := []string{"build", "-o", out}
		if raceEnabled {
			args = append(args, "-race")
		}
		cmd := exec.Command("go", append(args, pkg)...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			panic(err)
		}
		return out
	}
	relayBin = build("relay", "../cmd/relay")
	probeBin = build("probe", "./docker/probe")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type relay struct {
	t        *testing.T
	cmd      *exec.Cmd
	addr     string
	privAddr string
	base     string
	lines    chan string
	stderr   *lockedBuffer
	silent   bool
	exited   chan struct{}
	exitErr  error
}

func startRelay(t *testing.T, env ...string) *relay {
	t.Helper()
	return startBinary(t, relayBin, append([]string{"RELAY_ADDR=127.0.0.1:0", "RELAY_ADMISSION_RATE=100000"}, env...))
}

func startBinary(t *testing.T, bin string, env []string) *relay {
	t.Helper()
	cmd := exec.Command(bin)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "RELAY_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "GORACE=atexit_sleep_ms=0")
	cmd.Env = append(cmd.Env, env...)
	wantPrivate := false
	for _, kv := range env {
		wantPrivate = wantPrivate || strings.HasPrefix(kv, "RELAY_PRIVATE_ADDR=")
	}
	r := &relay{t: t, cmd: cmd, lines: make(chan string, 4), stderr: &lockedBuffer{}, exited: make(chan struct{})}
	cmd.Stderr = r.stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			select {
			case r.lines <- sc.Text():
			default:
			}
		}
	}()
	go func() {
		r.exitErr = cmd.Wait()
		close(r.exited)
	}()
	t.Cleanup(r.stop)
	t.Cleanup(r.expectReleased)
	timeout := time.After(10 * time.Second)
	for r.addr == "" || (wantPrivate && r.privAddr == "") {
		select {
		case line := <-r.lines:
			var ev struct{ Event, Address, Listener string }
			if err := json.Unmarshal([]byte(line), &ev); err != nil || ev.Event != "listening" {
				t.Fatalf("unexpected startup line %q", line)
			}
			if ev.Listener == "private" {
				r.privAddr = ev.Address
			} else {
				r.addr = ev.Address
				r.base = "ws://" + ev.Address
			}
		case <-r.exited:
			t.Fatalf("%s exited during startup: %v\n%s", filepath.Base(bin), r.exitErr, r.stderr)
		case <-timeout:
			t.Fatalf("%s did not report listening", filepath.Base(bin))
		}
	}
	return r
}

func (r *relay) adminAddr() string {
	if r.privAddr != "" {
		return r.privAddr
	}
	return r.addr
}

func (r *relay) signal(sig syscall.Signal) {
	r.expectSilent()
	_ = r.cmd.Process.Signal(sig)
}

func (r *relay) expectSilent() {
	if r.silent {
		return
	}
	r.silent = true
	select {
	case line := <-r.lines:
		r.t.Errorf("relay printed after startup: %s", line)
	default:
	}
	if stderr := r.stderr.String(); stderr != "" {
		r.t.Errorf("relay wrote to stderr before shutdown:\n%s", stderr)
	}
}

func (r *relay) waitExit(timeout time.Duration) error {
	select {
	case <-r.exited:
		return r.exitErr
	case <-time.After(timeout):
		return errors.New("relay did not exit")
	}
}

var shutdownLine = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d relay: (draining|stopped after \S+ with \d+ pairs force-closed)$`)

func (r *relay) stop() {
	select {
	case <-r.exited:
	default:
		r.signal(syscall.SIGTERM)
		select {
		case <-r.exited:
		case <-time.After(10 * time.Second):
			_ = r.cmd.Process.Kill()
			<-r.exited
		}
	}
	select {
	case line := <-r.lines:
		r.t.Errorf("relay printed during shutdown: %s", line)
	default:
	}
	for line := range strings.Lines(r.stderr.String()) {
		if !shutdownLine.MatchString(strings.TrimSuffix(line, "\n")) {
			r.t.Errorf("relay wrote more than its shutdown lines:\n%s", r.stderr)
			return
		}
	}
}

func (r *relay) get(path string) (int, []byte) {
	r.t.Helper()
	client := http.Client{Timeout: deadline}
	resp, err := client.Get("http://" + r.adminAddr() + path)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func (r *relay) metrics() map[string]float64 {
	r.t.Helper()
	_, body := r.get("/metrics")
	m := map[string]any{}
	if err := json.Unmarshal(body, &m); err != nil {
		r.t.Fatal(err)
	}
	out := map[string]float64{}
	for k, v := range m {
		if f, ok := v.(float64); ok {
			out[k] = f
		}
	}
	return out
}

var resourceGauges = []string{
	"activeHosts", "activePairs", "pendingPairs", "clientSlots",
	"openSockets", "openConnections", "openConnectionIPs",
}

func (r *relay) expectReleased() {
	select {
	case <-r.exited:
		return
	default:
	}
	if r.t.Failed() {
		return
	}
	r.waitMetrics("released resources", func(m map[string]float64) bool {
		for _, name := range resourceGauges {
			if v, ok := m[name]; !ok || v != 0 {
				return false
			}
		}
		return true
	})
}

func (r *relay) waitMetrics(desc string, pred func(map[string]float64) bool) map[string]float64 {
	r.t.Helper()
	end := time.Now().Add(deadline)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		m := r.metrics()
		if pred(m) {
			return m
		}
		if time.Now().After(end) {
			r.t.Fatalf("timed out waiting for %s: %v", desc, m)
		}
		<-tick.C
	}
}

func (r *relay) waitIdle() {
	r.t.Helper()
	r.waitMetrics("no pairs", func(m map[string]float64) bool { return m["activePairs"] == 0 && m["pendingPairs"] == 0 })
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func register(t *testing.T, r *relay) *endpoint.Host {
	t.Helper()
	return registerKey(t, r, newKey(t))
}

func registerKey(t *testing.T, r *relay, priv ed25519.PrivateKey) *endpoint.Host {
	t.Helper()
	h, err := endpoint.Register(r.base, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Control.Close() })
	return h
}

func connect(t *testing.T, r *relay, h *endpoint.Host) (*websocket.Conn, endpoint.Event) {
	t.Helper()
	c, resp, err := endpoint.Connect(r.base, h.ID)
	if err != nil {
		t.Fatalf("connect: %v (%s)", err, status(resp))
	}
	t.Cleanup(func() { c.Close() })
	ev := nextEvent(t, h, "incoming")
	return c, ev
}

func nextEvent(t *testing.T, h *endpoint.Host, typ string) endpoint.Event {
	t.Helper()
	ev, err := h.Next(deadline)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != typ {
		t.Fatalf("expected %s event, got %+v", typ, ev)
	}
	return ev
}

func accept(t *testing.T, h *endpoint.Host, ev endpoint.Event) *websocket.Conn {
	t.Helper()
	c, resp, err := h.Accept(ev)
	if err != nil {
		t.Fatalf("accept: %v (%s)", err, status(resp))
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func pairUp(t *testing.T, r *relay, h *endpoint.Host) (client, host *websocket.Conn, id string) {
	t.Helper()
	client, ev := connect(t, r, h)
	return client, accept(t, h, ev), ev.ConnectionID
}

func status(resp *http.Response) string {
	if resp == nil {
		return "no response"
	}
	return resp.Status
}

func expectStatus(t *testing.T, resp *http.Response, err error, codes ...int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected HTTP %v, connection was upgraded", codes)
	}
	for _, c := range codes {
		if resp != nil && resp.StatusCode == c {
			return
		}
	}
	t.Fatalf("expected HTTP %v, got %s (%v)", codes, status(resp), err)
}

type message struct {
	typ  int
	data []byte
}

func (m message) String() string {
	return fmt.Sprintf("type=%d len=%d", m.typ, len(m.data))
}

func send(t *testing.T, ws *websocket.Conn, m message) {
	t.Helper()
	_ = ws.SetWriteDeadline(time.Now().Add(deadline))
	if err := ws.WriteMessage(m.typ, m.data); err != nil {
		t.Fatal(err)
	}
}

func recv(t *testing.T, ws *websocket.Conn) message {
	t.Helper()
	_ = ws.SetReadDeadline(time.Now().Add(deadline))
	typ, data, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return message{typ, data}
}

func expectMessage(t *testing.T, ws *websocket.Conn, want message) {
	t.Helper()
	got := recv(t, ws)
	if got.typ != want.typ || !bytes.Equal(got.data, want.data) {
		t.Fatalf("message mismatch: got %v want %v", got, want)
	}
}

func readClose(ws *websocket.Conn) (*websocket.CloseError, error) {
	_ = ws.SetReadDeadline(time.Now().Add(deadline))
	for {
		_, _, err := ws.ReadMessage()
		if err == nil {
			continue
		}
		var ce *websocket.CloseError
		if errors.As(err, &ce) {
			return ce, nil
		}
		return nil, err
	}
}

func expectClose(t *testing.T, ws *websocket.Conn, codes ...int) *websocket.CloseError {
	t.Helper()
	ce, err := readClose(ws)
	if err != nil {
		t.Fatalf("expected close %v, got %v", codes, err)
	}
	if slices.Contains(codes, ce.Code) {
		return ce
	}
	t.Fatalf("expected close %v, got %d %q", codes, ce.Code, ce.Text)
	return nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
