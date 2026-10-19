//go:build dockere2e

package docker

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math"
	mrand "math/rand/v2"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/internal/endpoint"
)

const (
	supersededCode  = 4001
	streamWindow    = 64
	hostPing        = 250 * time.Millisecond
	hostDeadTimeout = time.Second
	backoffMin      = 50 * time.Millisecond
	backoffMax      = 500 * time.Millisecond
)

var dialer = &websocket.Dialer{HandshakeTimeout: 5 * time.Second, ReadBufferSize: 4096, WriteBufferSize: 4096}

type host struct {
	base       string
	priv       ed25519.PrivateKey
	id         string
	tag        string
	stopc      chan struct{}
	done       chan struct{}
	registered chan struct{}

	accepts     atomic.Int64
	acceptFails atomic.Int64

	mu         sync.Mutex
	ctrl       *websocket.Conn
	regs       int
	online     bool
	lostAt     time.Time
	regAt      []time.Time
	gaps       []time.Duration
	lossCodes  []int
	failReason []string
	attempts   int
}

func newHost(t *testing.T, tag string) *host {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return startHostKey(t, tag, priv)
}

func startHostKey(t *testing.T, tag string, priv ed25519.PrivateKey) *host {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	h := &host{base: st.base, priv: priv, id: endpoint.EndpointID(pub), tag: tag, stopc: make(chan struct{}), done: make(chan struct{}), registered: make(chan struct{}, 1)}
	st.remember(h.id, endpoint.B64(pub))
	go h.run()
	t.Cleanup(h.stop)
	return h
}

func (h *host) stop() {
	select {
	case <-h.stopc:
	default:
		close(h.stopc)
	}
	h.mu.Lock()
	if h.ctrl != nil {
		h.ctrl.Close()
	}
	h.mu.Unlock()
	<-h.done
}

func (h *host) waitRegistered(t *testing.T, timeout time.Duration) {
	t.Helper()
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		if h.isOnline() {
			return
		}
		select {
		case <-h.registered:
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("host %s not registered within %s (attempts %d, reasons %v)", h.tag, timeout, h.attemptCount(), h.reasons())
}

func (h *host) isOnline() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.online
}

func (h *host) registrations() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.regs
}

func (h *host) attemptCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.attempts
}

func (h *host) reasons() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.failReason...)
}

func (h *host) registeredAt(n int) (time.Time, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.regAt) < n {
		return time.Time{}, false
	}
	return h.regAt[n-1], true
}

func (h *host) reconnectGaps() []time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]time.Duration(nil), h.gaps...)
}

func (h *host) codes() []int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]int(nil), h.lossCodes...)
}

func (h *host) stopped() bool {
	select {
	case <-h.stopc:
		return true
	default:
		return false
	}
}

func (h *host) run() {
	defer close(h.done)
	backoff := backoffMin
	for !h.stopped() {
		ws, err := h.register()
		h.mu.Lock()
		h.attempts++
		h.mu.Unlock()
		if err != nil {
			h.mu.Lock()
			if len(h.failReason) < 32 {
				h.failReason = append(h.failReason, err.Error())
			}
			h.mu.Unlock()
			wait := backoff/2 + mrand.N(backoff/2+1)
			select {
			case <-h.stopc:
				return
			case <-time.After(wait):
			}
			backoff = min(2*backoff, backoffMax)
			continue
		}
		backoff = backoffMin
		h.mu.Lock()
		h.ctrl = ws
		h.regs++
		h.regAt = append(h.regAt, time.Now())
		h.online = true
		if !h.lostAt.IsZero() {
			h.gaps = append(h.gaps, time.Since(h.lostAt))
			h.lostAt = time.Time{}
		}
		h.mu.Unlock()
		select {
		case h.registered <- struct{}{}:
		default:
		}
		code := h.serve(ws)
		h.mu.Lock()
		h.online = false
		h.ctrl = nil
		h.lostAt = time.Now()
		h.lossCodes = append(h.lossCodes, code)
		h.mu.Unlock()
		if code == supersededCode {
			return
		}
	}
}

func (h *host) register() (*websocket.Conn, error) {
	pub := endpoint.B64(h.priv.Public().(ed25519.PublicKey))
	ws, resp, err := dialer.Dial(h.base+"/v1/control?publicKey="+pub, nil)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("control status %d", resp.StatusCode)
		}
		return nil, errors.New("control dial failed")
	}
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ch endpoint.Event
	if err := ws.ReadJSON(&ch); err != nil || ch.Type != "challenge" {
		ws.Close()
		return nil, errors.New("no challenge")
	}
	st.remember(ch.Nonce)
	if err := ws.WriteJSON(map[string]string{"type": "authenticate", "signature": endpoint.SignChallenge(h.priv, h.id, ch.Nonce)}); err != nil {
		ws.Close()
		return nil, err
	}
	var reg endpoint.Event
	if err := ws.ReadJSON(&reg); err != nil || reg.Type != "registered" || reg.EndpointID != h.id {
		ws.Close()
		var ce *websocket.CloseError
		if errors.As(err, &ce) {
			return nil, fmt.Errorf("registration closed %d", ce.Code)
		}
		return nil, errors.New("registration failed")
	}
	return ws, nil
}

func (h *host) serve(ws *websocket.Conn) (code int) {
	defer ws.Close()
	extend := func() { _ = ws.SetReadDeadline(time.Now().Add(hostDeadTimeout)) }
	extend()
	ws.SetPongHandler(func(string) error { extend(); return nil })
	stopPing := make(chan struct{})
	defer close(stopPing)
	go func() {
		t := time.NewTicker(hostPing)
		defer t.Stop()
		for {
			select {
			case <-stopPing:
				return
			case <-t.C:
				if ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(hostDeadTimeout)) != nil {
					return
				}
			}
		}
	}()
	for {
		var ev endpoint.Event
		if err := ws.ReadJSON(&ev); err != nil {
			var ce *websocket.CloseError
			if errors.As(err, &ce) {
				return ce.Code
			}
			return 0
		}
		extend()
		if ev.Type == "incoming" {
			st.remember(ev.ConnectionID, ev.Token)
			go h.accept(ev)
		}
	}
}

func (h *host) accept(ev endpoint.Event) {
	ws, resp, err := endpoint.Dialer.Dial(h.base+"/v1/accept?endpointId="+h.id+"&connectionId="+ev.ConnectionID+"&token="+ev.Token, nil)
	if err != nil {
		h.acceptFails.Add(1)
		h.mu.Lock()
		if len(h.failReason) < 32 {
			code := 0
			if resp != nil {
				code = resp.StatusCode
			}
			h.failReason = append(h.failReason, fmt.Sprintf("accept status %d", code))
		}
		h.mu.Unlock()
		return
	}
	h.accepts.Add(1)
	defer ws.Close()
	ws.SetReadLimit(1 << 20)
	prefix := []byte(h.tag + ":")
	for {
		typ, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if ws.WriteMessage(typ, append(append([]byte(nil), prefix...), data...)) != nil {
			return
		}
	}
}

func connect(base, endpointID string) (*websocket.Conn, int, error) {
	ws, resp, err := dialer.Dial(base+"/v1/connect?endpointId="+endpointID, nil)
	if err != nil {
		if resp != nil {
			return nil, resp.StatusCode, err
		}
		return nil, 0, err
	}
	ws.SetReadLimit(1 << 20)
	return ws, 101, nil
}

func payload(label string, k int) (int, []byte) {
	if k%3 == 2 {
		b := make([]byte, 16+(k*997)%4096)
		binary.BigEndian.PutUint64(b, uint64(k))
		copy(b[8:], label)
		_, _ = rand.Read(b[min(len(b), 8+len(label)):])
		return websocket.BinaryMessage, b
	}
	return websocket.TextMessage, []byte(fmt.Sprintf("%s-%06d", label, k))
}

func exchange(ws *websocket.Conn, h *host, label string, rounds int) error {
	for k := range rounds {
		typ, p := payload(label, k)
		_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := ws.WriteMessage(typ, p); err != nil {
			return fmt.Errorf("%s write %d: %w", label, k, err)
		}
		_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		gotTyp, got, err := ws.ReadMessage()
		if err != nil {
			return fmt.Errorf("%s read %d: %w", label, k, err)
		}
		want := append([]byte(h.tag+":"), p...)
		if gotTyp != typ || !bytes.Equal(got, want) {
			return fmt.Errorf("%s round %d: integrity or cross-delivery failure: got type=%d len=%d prefix=%q want type=%d len=%d prefix=%q", label, k, gotTyp, len(got), got[:min(len(got), 24)], typ, len(want), want[:min(len(want), 24)])
		}
	}
	return nil
}

func stream(ws *websocket.Conn, h *host, label string, n int) error {
	sent := make([][]byte, n)
	types := make([]int, n)
	for k := range n {
		types[k], sent[k] = payload(label, k)
	}
	errc := make(chan error, 1)
	window := make(chan struct{}, streamWindow)
	go func() {
		for k := range n {
			window <- struct{}{}
			_ = ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := ws.WriteMessage(types[k], sent[k]); err != nil {
				errc <- err
				return
			}
		}
		errc <- nil
	}()
	prefix := []byte(h.tag + ":")
	for k := range n {
		_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
		typ, got, err := ws.ReadMessage()
		<-window
		if err != nil {
			return fmt.Errorf("%s stream read %d/%d: %w", label, k, n, err)
		}
		if typ != types[k] || !bytes.HasPrefix(got, prefix) || !bytes.Equal(got[len(prefix):], sent[k]) {
			idx := slices.IndexFunc(sent, func(b []byte) bool { return bytes.HasPrefix(got, prefix) && bytes.Equal(got[len(prefix):], b) })
			return fmt.Errorf("%s stream message %d: corrupt, duplicated, reordered, or cross-delivered (matches sent index %d)", label, k, idx)
		}
	}
	return <-errc
}

func exchangeWithRetry(base string, h *host, label string, rounds int, within time.Duration) (int, error) {
	end := time.Now().Add(within)
	attempts := 0
	var last error
	for time.Now().Before(end) {
		attempts++
		ws, code, err := connect(base, h.id)
		if err != nil {
			last = fmt.Errorf("connect status %d: %w", code, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		err = exchange(ws, h, label, rounds)
		ws.Close()
		if err == nil {
			return attempts, nil
		}
		if strings.Contains(err.Error(), "integrity") {
			return attempts, err
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	return attempts, fmt.Errorf("host %s unreachable after %d attempts in %s: %v", h.tag, attempts, within, last)
}

type durations []time.Duration

func (d durations) summary() map[string]float64 {
	if len(d) == 0 {
		return map[string]float64{"count": 0}
	}
	s := slices.Clone(d)
	slices.Sort(s)
	q := func(p float64) float64 {
		i := int(math.Ceil(p*float64(len(s)))) - 1
		return float64(s[max(0, i)].Microseconds()) / 1000
	}
	return map[string]float64{"count": float64(len(s)), "p50Ms": q(0.5), "p95Ms": q(0.95), "maxMs": q(1)}
}

func httpStatus(t *testing.T, method, url string, hdr http.Header) int {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	maps.Copy(req.Header, hdr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func randomKey() string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return endpoint.B64(pub)
}

func dialCode(url string, hdr http.Header) int {
	ws, resp, err := dialer.Dial(url, hdr)
	if err == nil {
		ws.Close()
		return 101
	}
	if resp != nil {
		return resp.StatusCode
	}
	return 0
}

func countOf(codes []int, want int) int {
	n := 0
	for _, c := range codes {
		if c == want {
			n++
		}
	}
	return n
}
