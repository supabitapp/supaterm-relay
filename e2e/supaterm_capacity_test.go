package e2e

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/e2e/supaterm"
)

func connectMany(t *testing.T, r *relay, address string, n int) []*supaterm.Client {
	t.Helper()
	clients := make([]*supaterm.Client, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			clients[i], errs[i] = supaterm.Connect(context.Background(), supaterm.ClientConfig{RelayURL: r.base, Address: address})
		})
	}
	wg.Wait()
	for _, cl := range clients {
		if cl != nil {
			t.Cleanup(cl.Close)
		}
	}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
	}
	return clients
}

func TestSupatermHostServesItsSixtyFourPairCap(t *testing.T) {
	t.Parallel()
	r := startRelay(t, "RELAY_MAX_CLIENTS_PER_HOST_PER_IP=64")
	h := startSupatermHost(t, r, "busy")
	clients := connectMany(t, r, h.Address(), supaterm.MaxHostPairs)
	if m := r.metrics(); m["activePairs"] != supaterm.MaxHostPairs {
		t.Fatalf("metrics with a full host: %v", m)
	}
	var wg sync.WaitGroup
	for i, cl := range clients {
		wg.Go(func() {
			st, err := cl.Session.Open()
			if err != nil {
				t.Errorf("client %d open: %v", i, err)
				return
			}
			defer st.Close()
			_, _ = fmt.Fprintf(st, "GET /api/test/bytes/%d HTTP/1.1\r\nHost: supaterm.test\r\nConnection: close\r\n\r\n", 32<<10+i)
			resp, err := http.ReadResponse(bufio.NewReader(st), nil)
			if err != nil {
				t.Errorf("client %d: %v", i, err)
				return
			}
			body := readAll(t, resp)
			if len(body) != 32<<10+i {
				t.Errorf("client %d received %d bytes", i, len(body))
			}
		})
	}
	wg.Wait()

	expectFailure(t, r, h.Address(), supaterm.FailureRelayBusy, http.StatusServiceUnavailable)
	clients[0].Close()
	r.waitMetrics("a freed host slot", func(m map[string]float64) bool { return m["clientSlots"] == supaterm.MaxHostPairs-1 })
	if _, ce := connectSupaterm(t, r, h.Address()); ce != nil {
		t.Fatalf("freed slot: %v", ce)
	}
}

func TestSupatermPerNetworkQuotaReportsRelayBusy(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	h := startSupatermHost(t, r, "quota")
	connectMany(t, r, h.Address(), 16)
	expectFailure(t, r, h.Address(), supaterm.FailureRelayBusy, http.StatusTooManyRequests)
}

func TestSupatermHostAtCapacityLeavesExtraClientsHostOffline(t *testing.T) {
	t.Parallel()
	r := startRelay(t, "RELAY_MAX_CLIENTS_PER_HOST=80", "RELAY_MAX_CLIENTS_PER_HOST_PER_IP=80", "RELAY_PAIR_TIMEOUT_MS=300")
	h := startSupatermHost(t, r, "ignoring")
	connectMany(t, r, h.Address(), supaterm.MaxHostPairs)
	ce := expectFailure(t, r, h.Address(), supaterm.FailureHostOffline, http.StatusSwitchingProtocols)
	if ce.CloseCode != websocket.CloseTryAgainLater {
		t.Fatalf("ignored client closed with %d, want a 1013 close frame", ce.CloseCode)
	}
	if h.Ignored() != 1 {
		t.Fatalf("host ignored %d incoming events", h.Ignored())
	}
	r.waitMetrics("the ignored pair to expire", func(m map[string]float64) bool {
		return m["pendingPairs"] == 0 && m["activePairs"] == supaterm.MaxHostPairs
	})
}

func TestSupatermManyHostsStayIsolated(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	const hosts = 16
	var wg sync.WaitGroup
	for i := range hosts {
		env := fmt.Sprintf("host-%02d", i)
		h := startSupatermHost(t, r, env)
		for range 2 {
			c := newSupatermClient(t, r, h)
			wg.Go(func() {
				for range 5 {
					resp, err := c.http.Get(tunnelOrigin + "/.well-known/supaterm/environment")
					if err != nil {
						t.Errorf("%s: %v", env, err)
						return
					}
					body := readAll(t, resp)
					if want := fmt.Sprintf(`{"environmentId":%q}`, env); string(body) != want+"\n" {
						t.Errorf("%s client reached %s", env, body)
					}
				}
			})
		}
	}
	wg.Wait()
	if m := r.metrics(); m["activeHosts"] != hosts || m["activePairs"] != 2*hosts {
		t.Fatalf("metrics with %d hosts: %v", hosts, m)
	}
}
