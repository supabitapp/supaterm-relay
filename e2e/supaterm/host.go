package supaterm

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/internal/endpoint"
)

const (
	StatusConnecting = "connecting"
	StatusRegistered = "registered"
	StatusSuperseded = "superseded"
	StatusStopped    = "stopped"

	MaxHostPairs       = 64
	controlMaxPayload  = 16384
	dialTimeout        = 10 * time.Second
	readyTimeout       = 15 * time.Second
	acceptTimeout      = 15 * time.Second
	controlHeartbeat   = 15 * time.Second
	maxRetryDelay      = 30 * time.Second
	closeSupersededReg = 4001
)

type HostConfig struct {
	Identity  ed25519.PrivateKey
	RelayURL  string
	RetryBase time.Duration
	Heartbeat time.Duration
	KeepAlive time.Duration
	Random    io.Reader
}

type Host struct {
	cfg HostConfig
	ID  string

	mu         sync.Mutex
	changed    *sync.Cond
	stopped    bool
	control    *websocket.Conn
	retry      *time.Timer
	attempts   int
	pairs      map[string]*hostPair
	statuses   []string
	violations []string
	accepted   []*Stream
	version    int

	registrations atomic.Int64
	sessions      atomic.Int64
	ignored       atomic.Int64
	dials         atomic.Int64
}

func StartHost(cfg HostConfig) *Host {
	if cfg.RetryBase == 0 {
		cfg.RetryBase = time.Second
	}
	if cfg.Heartbeat == 0 {
		cfg.Heartbeat = controlHeartbeat
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	h := &Host{cfg: cfg, ID: endpoint.EndpointID(cfg.Identity.Public().(ed25519.PublicKey)), pairs: map[string]*hostPair{}}
	h.changed = sync.NewCond(&h.mu)
	go h.connect()
	return h
}

func (h *Host) Address() string {
	return Address(h.cfg.Identity.Public().(ed25519.PublicKey))
}

func (h *Host) notify() {
	h.version++
	h.changed.Broadcast()
}

func (h *Host) setStatus(state string) {
	h.statuses = append(h.statuses, state)
	h.notify()
}

func (h *Host) connect() {
	h.mu.Lock()
	if h.stopped {
		h.mu.Unlock()
		return
	}
	h.setStatus(StatusConnecting)
	h.mu.Unlock()
	h.dials.Add(1)
	pub := h.cfg.Identity.Public().(ed25519.PublicKey)
	dialer := websocket.Dialer{HandshakeTimeout: dialTimeout}
	ws, _, err := dialer.Dial(h.cfg.RelayURL+"/v1/control?publicKey="+endpoint.B64(pub), nil)
	h.mu.Lock()
	if err != nil {
		h.scheduleRetry()
		h.mu.Unlock()
		return
	}
	if h.stopped {
		h.mu.Unlock()
		ws.Close()
		return
	}
	h.control = ws
	h.mu.Unlock()
	ws.SetReadLimit(controlMaxPayload)
	h.runControl(ws)
}

func (h *Host) runControl(ws *websocket.Conn) {
	var alive atomic.Bool
	alive.Store(true)
	ready := time.AfterFunc(readyTimeout, func() { ws.Close() })
	stopHeartbeat := make(chan struct{})
	go func() {
		tick := time.NewTicker(h.cfg.Heartbeat)
		defer tick.Stop()
		for {
			select {
			case <-stopHeartbeat:
				return
			case <-tick.C:
			}
			if !alive.Swap(false) {
				h.violation("relay did not answer the control heartbeat")
				ws.Close()
				return
			}
			_ = ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait))
		}
	}()
	ws.SetPongHandler(func(string) error {
		alive.Store(true)
		return nil
	})
	var challenged, registered bool
	code := websocket.CloseAbnormalClosure
	for {
		typ, data, err := ws.ReadMessage()
		if err != nil {
			var ce *websocket.CloseError
			if errors.As(err, &ce) {
				code = ce.Code
			}
			break
		}
		h.mu.Lock()
		current := h.control == ws && !h.stopped
		h.mu.Unlock()
		if !current {
			continue
		}
		if err := h.handleControl(ws, typ, data, &challenged, &registered, ready); err != nil {
			h.violation(err.Error())
			ws.Close()
		}
	}
	ready.Stop()
	close(stopHeartbeat)
	h.controlClosed(ws, code)
}

type controlEvent struct {
	Type         string  `json:"type"`
	Nonce        *string `json:"nonce"`
	EndpointID   *string `json:"endpointId"`
	ConnectionID *string `json:"connectionId"`
	Token        *string `json:"token"`
}

func (h *Host) handleControl(ws *websocket.Conn, typ int, data []byte, challenged, registered *bool, ready *time.Timer) error {
	if typ != websocket.TextMessage {
		return errors.New("invalid control message: binary")
	}
	var ev controlEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		return fmt.Errorf("invalid control message: %w", err)
	}
	switch {
	case ev.Type == "challenge" && ev.Nonce != nil && !*challenged:
		nonce, err := decodeBase64(*ev.Nonce)
		if err != nil || len(nonce) != 32 {
			return errors.New("invalid challenge")
		}
		*challenged = true
		sig := endpoint.SignChallenge(h.cfg.Identity, h.ID, *ev.Nonce)
		msg, _ := json.Marshal(struct {
			Type      string `json:"type"`
			Signature string `json:"signature"`
		}{"authenticate", sig})
		_ = ws.SetWriteDeadline(time.Now().Add(writeWait))
		return ws.WriteMessage(websocket.TextMessage, msg)
	case ev.Type == "registered" && ev.EndpointID != nil && *challenged && !*registered && *ev.EndpointID == h.ID:
		*registered = true
		ready.Stop()
		h.registrations.Add(1)
		h.mu.Lock()
		h.attempts = 0
		h.setStatus(StatusRegistered)
		h.mu.Unlock()
		return nil
	case ev.Type == "incoming" && ev.ConnectionID != nil && ev.Token != nil && *registered:
		h.accept(*ev.ConnectionID, *ev.Token)
		return nil
	case ev.Type == "closed" && ev.ConnectionID != nil && *registered:
		h.mu.Lock()
		p := h.pairs[*ev.ConnectionID]
		h.mu.Unlock()
		if p != nil {
			p.stop()
		}
		return nil
	}
	return fmt.Errorf("invalid control event %q", data)
}

func (h *Host) controlClosed(ws *websocket.Conn, code int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.control != ws || h.stopped {
		return
	}
	h.control = nil
	if code == closeSupersededReg {
		h.stopped = true
		h.setStatus(StatusSuperseded)
		return
	}
	h.scheduleRetry()
}

func (h *Host) scheduleRetry() {
	if h.stopped {
		return
	}
	jitter, _ := rand.Int(rand.Reader, big.NewInt(401))
	delay := min(maxRetryDelay, h.cfg.RetryBase<<min(h.attempts, 5))
	delay = time.Duration(float64(delay) * (0.8 + float64(jitter.Int64())/1000))
	h.attempts++
	h.retry = time.AfterFunc(delay, h.connect)
	h.setStatus(StatusConnecting)
}

func (h *Host) accept(connectionID, token string) {
	h.mu.Lock()
	if _, dup := h.pairs[connectionID]; dup || len(h.pairs) >= MaxHostPairs {
		h.mu.Unlock()
		h.ignored.Add(1)
		return
	}
	p := &hostPair{host: h, id: connectionID}
	p.timer = time.AfterFunc(acceptTimeout, p.stop)
	h.pairs[connectionID] = p
	h.notify()
	h.mu.Unlock()
	go p.run(token)
}

type hostPair struct {
	host  *Host
	id    string
	timer *time.Timer
	once  sync.Once

	mu      sync.Mutex
	stopped bool
	ws      *websocket.Conn
	session *Session
}

func (p *hostPair) adopt(ws *websocket.Conn, session *Session) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return false
	}
	p.ws, p.session = ws, session
	return true
}

func (p *hostPair) stop() {
	p.once.Do(func() {
		p.mu.Lock()
		p.stopped = true
		ws, session := p.ws, p.session
		p.mu.Unlock()
		p.timer.Stop()
		if session != nil {
			session.Close(nil)
		}
		if ws != nil {
			ws.Close()
		}
		h := p.host
		h.mu.Lock()
		delete(h.pairs, p.id)
		h.notify()
		h.mu.Unlock()
	})
}

func (p *hostPair) run(token string) {
	defer p.stop()
	h := p.host
	url := h.cfg.RelayURL + "/v1/accept?endpointId=" + h.ID + "&connectionId=" + p.id + "&token=" + token
	ws, _, err := (&websocket.Dialer{HandshakeTimeout: dialTimeout}).Dial(url, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(MaxRecordBytes)
	if !p.adopt(ws, nil) {
		ws.Close()
		return
	}
	session, err := p.handshake(ws)
	if err != nil {
		return
	}
	if !p.adopt(ws, session) {
		session.Close(nil)
		return
	}
	for {
		typ, data, err := ws.ReadMessage()
		if err != nil || typ != websocket.BinaryMessage {
			return
		}
		session.Receive(data)
	}
}

func (p *hostPair) handshake(ws *websocket.Conn) (*Session, error) {
	h := p.host
	typ, data, err := ws.ReadMessage()
	if err != nil {
		return nil, err
	}
	if typ != websocket.TextMessage || len(data) > maxHandshakeBytes {
		return nil, errors.New("invalid relay handshake")
	}
	welcome, cipher, err := AcceptClientHandshake(data, h.cfg.Identity, h.cfg.Random)
	if err != nil {
		return nil, err
	}
	p.timer.Stop()
	_ = ws.SetWriteDeadline(time.Now().Add(writeWait))
	if err := ws.WriteMessage(websocket.TextMessage, welcome); err != nil {
		return nil, err
	}
	_ = ws.SetWriteDeadline(time.Time{})
	h.sessions.Add(1)
	h.mu.Lock()
	h.notify()
	h.mu.Unlock()
	return NewSession(SessionConfig{
		Cipher:    cipher,
		KeepAlive: h.cfg.KeepAlive,
		Send:      func(b []byte) error { return ws.WriteMessage(websocket.BinaryMessage, b) },
		OnStream:  h.enqueue,
		OnClose:   func(error) { p.stop() },
	}), nil
}

func (h *Host) enqueue(st *Stream) {
	h.mu.Lock()
	h.accepted = append(h.accepted, st)
	h.notify()
	h.mu.Unlock()
}

func (h *Host) violation(reason string) {
	h.mu.Lock()
	h.violations = append(h.violations, reason)
	h.notify()
	h.mu.Unlock()
}

func (h *Host) Accept() (net.Conn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for len(h.accepted) == 0 && !h.stopped {
		h.changed.Wait()
	}
	if len(h.accepted) == 0 {
		return nil, net.ErrClosed
	}
	st := h.accepted[0]
	h.accepted = h.accepted[1:]
	return st, nil
}

func (h *Host) Addr() net.Addr { return tunnelAddr{} }

func (h *Host) DropControl() {
	h.mu.Lock()
	control := h.control
	h.mu.Unlock()
	if control != nil {
		control.Close()
	}
}

func (h *Host) Close() error {
	h.Stop()
	return nil
}

func (h *Host) Stop() {
	h.mu.Lock()
	if slices.Contains(h.statuses, StatusStopped) {
		h.mu.Unlock()
		return
	}
	h.stopped = true
	if h.retry != nil {
		h.retry.Stop()
	}
	control := h.control
	h.control = nil
	pairs := slices.Collect(maps.Values(h.pairs))
	h.setStatus(StatusStopped)
	h.mu.Unlock()
	if control != nil {
		control.Close()
	}
	for _, p := range pairs {
		p.stop()
	}
}

func (h *Host) Status() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.statuses) == 0 {
		return ""
	}
	return h.statuses[len(h.statuses)-1]
}

func (h *Host) Statuses() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.statuses)
}

func (h *Host) Violations() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.violations)
}

func (h *Host) Pairs() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.pairs)
}

func (h *Host) Registrations() int64 { return h.registrations.Load() }
func (h *Host) Sessions() int64      { return h.sessions.Load() }
func (h *Host) Ignored() int64       { return h.ignored.Load() }
func (h *Host) Dials() int64         { return h.dials.Load() }

func (h *Host) WaitFor(timeout time.Duration, cond func(h *Host) bool) bool {
	end := time.Now().Add(timeout)
	wake := time.AfterFunc(timeout, func() {
		h.mu.Lock()
		h.notify()
		h.mu.Unlock()
	})
	defer wake.Stop()
	for {
		h.mu.Lock()
		seen := h.version
		h.mu.Unlock()
		if cond(h) {
			return true
		}
		if !time.Now().Before(end) {
			return false
		}
		h.mu.Lock()
		for h.version == seen {
			h.changed.Wait()
		}
		h.mu.Unlock()
	}
}

func (h *Host) WaitStatus(state string, timeout time.Duration) bool {
	return h.WaitFor(timeout, func(h *Host) bool { return h.Status() == state })
}
