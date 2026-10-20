//go:build supaterminterop

package interop

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/supabitapp/supaterm-relay/e2e/supaterm"
)

const (
	wrappedRelayEnv = "SUPATERM_INTEROP_RELAY"
	relayExitLogEnv = "SUPATERM_INTEROP_RELAY_EXITS"
)

func TestMain(m *testing.M) {
	if relay := os.Getenv(wrappedRelayEnv); relay != "" {
		os.Exit(superviseRelay(relay, os.Getenv(relayExitLogEnv)))
	}
	os.Exit(m.Run())
}

func superviseRelay(relay, exitLog string) int {
	cmd := exec.Command(relay, os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	if err := cmd.Start(); err != nil {
		return 1
	}
	go func() {
		for sig := range signals {
			_ = cmd.Process.Signal(sig)
		}
	}()
	_ = cmd.Wait()
	code := cmd.ProcessState.ExitCode()
	if log, err := os.OpenFile(exitLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
		fmt.Fprintln(log, code)
		log.Close()
	}
	return code
}

type fixtureConfig struct {
	RelayURL   string `json:"relayUrl"`
	NodeOrigin string `json:"nodeOrigin"`
	Image      string `json:"image"`
	Video      string `json:"video"`
}

type fixture struct {
	cfg        fixtureConfig
	exitLog    string
	relays     int
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	lines      chan string
	exited     chan error
	stderrPath string
	client     *http.Client
}

func startFixture(t *testing.T) *fixture {
	t.Helper()
	dir := os.Getenv("SUPATERM_DIR")
	if dir == "" {
		t.Skip("set SUPATERM_DIR to a Supaterm checkout with installed dependencies")
	}
	relay := os.Getenv("RELAY_TEST_BINARY")
	if relay == "" {
		relay = filepath.Join(t.TempDir(), "relay")
		build := exec.Command("go", "build", "-race", "-o", relay, "../../cmd/relay")
		build.Stdout, build.Stderr = os.Stderr, os.Stderr
		if err := build.Run(); err != nil {
			t.Fatal(err)
		}
	}
	logs := t.TempDir()
	stderr, err := os.Create(filepath.Join(logs, "fixture.stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	f := &fixture{relays: 1, exitLog: filepath.Join(logs, "relay.exits"), stderrPath: stderr.Name(), lines: make(chan string, 16), exited: make(chan error, 1)}
	f.cmd = exec.Command("node", "apps/server/src/relay/testing/nativeFixture.ts")
	f.cmd.Dir = dir
	f.cmd.Env = append(os.Environ(),
		"RELAY_TEST_BINARY="+os.Args[0],
		wrappedRelayEnv+"="+relay,
		relayExitLogEnv+"="+f.exitLog,
		"GORACE=halt_on_error=1 atexit_sleep_ms=0",
	)
	f.cmd.Stderr = stderr
	if f.stdin, err = f.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	stdout, err := f.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		lines := bufio.NewScanner(stdout)
		for lines.Scan() {
			f.lines <- lines.Text()
		}
		close(f.lines)
		f.exited <- f.cmd.Wait()
	}()
	t.Cleanup(func() { f.stop(t) })
	if err := json.Unmarshal([]byte(f.line(t)), &f.cfg); err != nil {
		t.Fatalf("fixture config: %v", err)
	}
	f.client = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 64}}
	return f
}

func (f *fixture) stderr() string {
	b, _ := os.ReadFile(f.stderrPath)
	return string(b)
}

func (f *fixture) line(t *testing.T) string {
	t.Helper()
	select {
	case line, ok := <-f.lines:
		if !ok {
			t.Fatalf("fixture exited\n%s", f.stderr())
		}
		return line
	case <-time.After(60 * time.Second):
		t.Fatalf("fixture did not answer\n%s", f.stderr())
		return ""
	}
}

func (f *fixture) command(t *testing.T, op string) {
	t.Helper()
	if _, err := fmt.Fprintf(f.stdin, "{\"op\":%q}\n", op); err != nil {
		t.Fatal(err)
	}
	f.line(t)
	f.client.CloseIdleConnections()
}

func (f *fixture) stop(t *testing.T) {
	_, _ = io.WriteString(f.stdin, "{\"op\":\"stop\"}\n")
	_ = f.stdin.Close()
	select {
	case err := <-f.exited:
		if err != nil {
			t.Errorf("fixture exited with %v\n%s", err, f.stderr())
		}
	case <-time.After(30 * time.Second):
		_ = f.cmd.Process.Kill()
		<-f.exited
		t.Errorf("fixture did not stop\n%s", f.stderr())
	}
	exits, _ := os.ReadFile(f.exitLog)
	if codes := strings.Fields(string(exits)); len(codes) != f.relays || slices.ContainsFunc(codes, func(c string) bool { return c != "0" }) {
		t.Errorf("relay processes exited with %v, want %d clean exits\n%s", codes, f.relays, f.stderr())
	}
}

func (f *fixture) get(path string) (int64, error) {
	resp, err := f.client.Get(f.cfg.NodeOrigin + path)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err == nil && resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("GET %s: %s (relay error %q)", path, resp.Status, resp.Header.Get("X-Supaterm-Relay-Error"))
	}
	return n, err
}

func (f *fixture) metrics(t *testing.T) map[string]float64 {
	t.Helper()
	resp, err := f.client.Get("http" + strings.TrimPrefix(f.cfg.RelayURL, "ws") + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	m := map[string]float64{}
	for k, v := range raw {
		if n, ok := v.(float64); ok {
			m[k] = n
		}
	}
	return m
}

func (f *fixture) eventually(t *testing.T, desc string, try func() error) {
	t.Helper()
	end := time.Now().Add(30 * time.Second)
	for {
		f.client.CloseIdleConnections()
		err := try()
		if err == nil {
			return
		}
		if time.Now().After(end) {
			t.Fatalf("%s: %v\n%s", desc, err, f.stderr())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func parallel(t *testing.T, n int, fn func() error) {
	t.Helper()
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			if err := fn(); err != nil {
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

func TestSupatermThroughTheRelay(t *testing.T) {
	f := startFixture(t)
	environment := func() error {
		_, err := f.get("/.well-known/supaterm/environment")
		return err
	}
	image := func() error {
		_, err := f.get(f.cfg.Image)
		return err
	}

	t.Run("cold requests share one tunnel", func(t *testing.T) {
		parallel(t, 20, environment)
	})

	fixture := supaterm.Fixture{HTTP: f.client, Origin: f.cfg.NodeOrigin, Environment: "relay-interop-environment"}
	for _, check := range fixture.Checks() {
		t.Run(check.Name, func(t *testing.T) {
			if err := check.Run(); err != nil {
				t.Fatalf("%v\n%s", err, f.stderr())
			}
		})
	}

	t.Run("concurrent images", func(t *testing.T) {
		parallel(t, 20, image)
	})

	t.Run("concurrent videos", func(t *testing.T) {
		parallel(t, 4, func() error {
			n, err := f.get(f.cfg.Video)
			if err == nil && n != supaterm.VideoBytes {
				err = fmt.Errorf("video of %d bytes", n)
			}
			return err
		})
		if m := f.metrics(t); m["forwardedBytes"] < 6*supaterm.VideoBytes || m["activePairs"] != 1 || m["activeHosts"] != 1 {
			t.Fatalf("relay did not carry the transfers through one pair: %v", m)
		}
	})

	t.Run("relay restart", func(t *testing.T) {
		f.command(t, "restartRelay")
		f.relays++
		f.eventually(t, "requests after a relay restart", image)
		if err := environment(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("host restart", func(t *testing.T) {
		f.command(t, "restartHost")
		f.eventually(t, "requests after a host restart", environment)
		if err := image(); err != nil {
			t.Fatal(err)
		}
	})
}
