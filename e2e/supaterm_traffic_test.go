package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/supabitapp/supaterm-relay/e2e/supaterm"
)

func TestSupatermFixtureRoutesThroughTheRelay(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	h := startSupatermHost(t, r, "fixture-environment")
	c := newSupatermClient(t, r, h)
	fixture := supaterm.Fixture{HTTP: c.http, Origin: tunnelOrigin, Dial: c.DialContext, Environment: "fixture-environment"}
	for _, check := range fixture.Checks() {
		if err := check.Run(); err != nil {
			t.Fatalf("%s: %v", check.Name, err)
		}
	}
	if c.Dials() != 1 || h.Sessions() != 1 {
		t.Fatalf("%d dials and %d host sessions, want one tunnel", c.Dials(), h.Sessions())
	}
	if err := c.session(t).Err(); err != nil {
		t.Fatalf("tunnel failed: %v", err)
	}
	if m := r.metrics(); m["activePairs"] != 1 || m["forwardedBytes"] < 2*supaterm.VideoBytes {
		t.Fatalf("metrics after traffic: %v", m)
	}
}

func TestSupatermColdRequestsShareOneDial(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	h := startSupatermHost(t, r, "cold")
	c := newSupatermClient(t, r, h)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Go(func() {
			resp, err := c.http.Get(tunnelOrigin + "/.well-known/supaterm/environment")
			if err != nil {
				errs <- err
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("status %s", resp.Status)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if c.Dials() != 1 || h.Sessions() != 1 || r.metrics()["activePairs"] != 1 {
		t.Fatalf("%d dials, %d host sessions, %v pairs", c.Dials(), h.Sessions(), r.metrics()["activePairs"])
	}
}

func TestSupatermParallelStreamsShareOneSession(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	h := startSupatermHost(t, r, "parallel")
	c := newSupatermClient(t, r, h)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := range 48 {
		wg.Go(func() {
			n := 64<<10 + i*37<<10
			resp, err := c.http.Get(fmt.Sprintf("%s/api/test/bytes/%d", tunnelOrigin, n))
			if err != nil {
				errs <- err
				return
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || !bytes.Equal(body, supaterm.Pattern(0, n)) {
				errs <- fmt.Errorf("download %d: %d bytes, %v", i, len(body), err)
			}
		})
	}
	for i := range 8 {
		wg.Go(func() {
			payload := randomBytes(512<<10 + i*1000)
			resp, err := c.http.Post(tunnelOrigin+"/api/test/echo", "application/octet-stream", bytes.NewReader(payload))
			if err != nil {
				errs <- err
				return
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || !bytes.Equal(body, payload) {
				errs <- fmt.Errorf("echo %d: %d bytes, %v", i, len(body), err)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if c.Dials() != 1 || h.Sessions() != 1 {
		t.Fatalf("%d dials and %d host sessions", c.Dials(), h.Sessions())
	}
	if err := c.session(t).Err(); err != nil {
		t.Fatalf("tunnel failed: %v", err)
	}
}

func TestSupatermFullDuplexTransfer(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	h := startSupatermHost(t, r, "duplex")
	c := newSupatermClient(t, r, h)
	const size = 24 << 20
	body, sink := io.Pipe()
	sum := sha256.New()
	go func() {
		chunk := make([]byte, 128<<10)
		for sent := 0; sent < size; sent += len(chunk) {
			_, _ = rand.Read(chunk)
			sum.Write(chunk)
			if _, err := sink.Write(chunk); err != nil {
				return
			}
		}
		sink.Close()
	}()
	req, _ := http.NewRequest(http.MethodPost, tunnelOrigin+"/api/test/echo", body)
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	echoed := sha256.New()
	n, err := io.Copy(echoed, resp.Body)
	if err != nil || n != size {
		t.Fatalf("echoed %d bytes: %v", n, err)
	}
	if !bytes.Equal(echoed.Sum(nil), sum.Sum(nil)) {
		t.Fatal("echoed bytes differ")
	}
}

func TestSupatermProbeAnswersPromptlyUnderLoad(t *testing.T) {
	t.Parallel()
	r := startRelay(t)
	h := startSupatermHost(t, r, "probe")
	c := newSupatermClient(t, r, h)
	s := c.session(t)

	stalled, err := c.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(stalled, fmt.Sprintf("GET /api/test/bytes/%d HTTP/1.1\r\nHost: supaterm.test\r\n\r\n", 8<<20))

	ctx := t.Context()
	go func() {
		for ctx.Err() == nil {
			resp, err := c.http.Get(fmt.Sprintf("%s/api/test/bytes/%d", tunnelOrigin, 4<<20))
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond)
	for range 10 {
		if _, err := s.Ping(2 * time.Second); err != nil {
			t.Fatalf("encrypted probe failed under load: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = stalled.Close()
}
