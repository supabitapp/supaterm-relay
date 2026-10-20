package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/supabitapp/supaterm-relay/e2e/supaterm"
)

const tunnelOrigin = "http://supaterm.test"

type supatermHost struct {
	*supaterm.Host
	server *http.Server
}

func startSupatermHost(t *testing.T, r *relay, environmentID string, configure ...func(*supaterm.HostConfig)) *supatermHost {
	t.Helper()
	return startSupatermHostKey(t, r, newKey(t), environmentID, configure...)
}

func startSupatermHostKey(t *testing.T, r *relay, identity ed25519.PrivateKey, environmentID string, configure ...func(*supaterm.HostConfig)) *supatermHost {
	t.Helper()
	cfg := supaterm.HostConfig{Identity: identity, RelayURL: r.base, RetryBase: 10 * time.Millisecond}
	for _, f := range configure {
		f(&cfg)
	}
	h := &supatermHost{Host: supaterm.StartHost(cfg), server: &http.Server{Handler: supaterm.FixtureHandler(environmentID)}}
	go func() { _ = h.server.Serve(h.Host) }()
	t.Cleanup(func() {
		h.Stop()
		_ = h.server.Close()
		if v := h.Violations(); len(v) > 0 {
			t.Errorf("host saw relay protocol violations: %q", v)
		}
	})
	if !h.WaitStatus(supaterm.StatusRegistered, deadline) {
		t.Fatalf("host did not register: %v", h.Statuses())
	}
	return h
}

type supatermClient struct {
	*supaterm.Connector
	http *http.Client
}

func newSupatermClient(t *testing.T, r *relay, h *supatermHost) *supatermClient {
	t.Helper()
	conn := supaterm.NewConnector(supaterm.ClientConfig{RelayURL: r.base, Address: h.Address()})
	c := &supatermClient{Connector: conn, http: conn.HTTPClient()}
	c.http.Timeout = 60 * time.Second
	t.Cleanup(func() {
		c.http.CloseIdleConnections()
		conn.Close()
	})
	return c
}

func (c *supatermClient) environment(t *testing.T) string {
	t.Helper()
	resp, err := c.http.Get(tunnelOrigin + "/.well-known/supaterm/environment")
	if err != nil {
		t.Fatal(err)
	}
	var env struct{ EnvironmentID string }
	if err := json.Unmarshal(readAll(t, resp), &env); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("environment: %s %v", resp.Status, err)
	}
	return env.EnvironmentID
}

func (c *supatermClient) session(t *testing.T) *supaterm.Session {
	t.Helper()
	s, err := c.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func connectSupaterm(t *testing.T, r *relay, address string) (*supaterm.Client, *supaterm.ConnectError) {
	t.Helper()
	cl, err := supaterm.Connect(context.Background(), supaterm.ClientConfig{RelayURL: r.base, Address: address})
	if err == nil {
		t.Cleanup(cl.Close)
		return cl, nil
	}
	var ce *supaterm.ConnectError
	if !errors.As(err, &ce) {
		t.Fatalf("connect: %v", err)
	}
	return nil, ce
}

func expectFailure(t *testing.T, r *relay, address, failure string, status int) *supaterm.ConnectError {
	t.Helper()
	_, ce := connectSupaterm(t, r, address)
	if ce == nil {
		t.Fatalf("connected, want %s (HTTP %d)", failure, status)
	}
	if ce.Failure != failure || ce.Status != status {
		t.Fatalf("got %v, want %s (HTTP %d)", ce, failure, status)
	}
	return ce
}

func waitClosed(t *testing.T, s *supaterm.Session) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(2 * deadline):
		t.Fatal("tunnel session stayed open")
	}
}

func waitHost(t *testing.T, h *supatermHost, desc string, cond func(*supaterm.Host) bool) {
	t.Helper()
	if !h.WaitFor(deadline, cond) {
		t.Fatalf("timed out waiting for %s: %v", desc, h.Statuses())
	}
}

func readAll(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}
	return body
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}
