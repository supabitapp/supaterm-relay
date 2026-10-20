package supaterm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/internal/endpoint"
)

const (
	FailureHostOffline = "host-offline"
	FailureRelayBusy   = "relay-busy"
	FailureTimeout     = "relay-timeout"
	FailureUnreachable = "relay-unreachable"

	HandshakeTimeout = 15 * time.Second
	writeWait        = 5 * time.Second
)

type ConnectError struct {
	Failure   string
	Status    int
	CloseCode int
	Err       error
}

func (e *ConnectError) Error() string {
	return fmt.Sprintf("%s (status %d, close %d): %v", e.Failure, e.Status, e.CloseCode, e.Err)
}

func (e *ConnectError) Unwrap() error { return e.Err }

func failureFor(status int) string {
	switch status {
	case http.StatusSwitchingProtocols, http.StatusNotFound:
		return FailureHostOffline
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return FailureRelayBusy
	}
	return FailureUnreachable
}

type ClientConfig struct {
	RelayURL         string
	Address          string
	HandshakeTimeout time.Duration
	KeepAlive        time.Duration
	Random           io.Reader
}

type Client struct {
	Session *Session
	ws      *websocket.Conn
	once    sync.Once
}

func Connect(ctx context.Context, cfg ClientConfig) (*Client, error) {
	identity, err := ParseAddress(cfg.Address)
	if err != nil {
		return nil, err
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = HandshakeTimeout
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	hs, err := NewClientHandshake(identity, cfg.Random)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()
	url := cfg.RelayURL + "/v1/connect?endpointId=" + endpoint.EndpointID(ed25519.PublicKey(identity))
	ws, resp, err := websocket.DefaultDialer.DialContext(ctx, url, nil)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		failure := failureFor(status)
		if ctx.Err() != nil {
			failure = FailureTimeout
		}
		return nil, &ConnectError{Failure: failure, Status: status, Err: err}
	}
	if err := ws.WriteMessage(websocket.TextMessage, hs.Hello); err != nil {
		ws.Close()
		return nil, &ConnectError{Failure: FailureHostOffline, Status: http.StatusSwitchingProtocols, Err: err}
	}
	deadline, _ := ctx.Deadline()
	_ = ws.SetReadDeadline(deadline)
	stopWatch := context.AfterFunc(ctx, func() { _ = ws.SetReadDeadline(time.Now()) })
	typ, data, err := ws.ReadMessage()
	stopWatch()
	if err != nil {
		ws.Close()
		var ce *websocket.CloseError
		var ne net.Error
		switch {
		case errors.As(err, &ce):
			return nil, &ConnectError{Failure: FailureHostOffline, Status: http.StatusSwitchingProtocols, CloseCode: ce.Code, Err: err}
		case errors.As(err, &ne) && ne.Timeout():
			return nil, &ConnectError{Failure: FailureTimeout, Status: http.StatusSwitchingProtocols, Err: err}
		}
		return nil, &ConnectError{Failure: FailureHostOffline, Status: http.StatusSwitchingProtocols, CloseCode: websocket.CloseAbnormalClosure, Err: err}
	}
	if typ != websocket.TextMessage || len(data) > maxHandshakeBytes {
		ws.Close()
		return nil, &ConnectError{Failure: FailureUnreachable, Status: http.StatusSwitchingProtocols, Err: errors.New("invalid relay handshake")}
	}
	cipher, err := hs.Finish(data)
	if err != nil {
		ws.Close()
		return nil, &ConnectError{Failure: FailureUnreachable, Status: http.StatusSwitchingProtocols, Err: err}
	}
	_ = ws.SetReadDeadline(time.Time{})
	c := &Client{ws: ws}
	c.Session = NewSession(SessionConfig{
		Cipher:    cipher,
		Initiator: true,
		KeepAlive: cfg.KeepAlive,
		Send:      func(b []byte) error { return ws.WriteMessage(websocket.BinaryMessage, b) },
		OnClose:   func(error) { c.closeSocket() },
	})
	go c.read()
	return c, nil
}

func (c *Client) read() {
	for {
		typ, data, err := c.ws.ReadMessage()
		if err != nil {
			c.Session.Close(err)
			c.ws.Close()
			return
		}
		if typ != websocket.BinaryMessage {
			c.Session.Close(errors.New("unencrypted relay message"))
			continue
		}
		c.Session.Receive(data)
	}
}

func (c *Client) closeSocket() {
	c.sendClose([]byte{})
}

func (c *Client) sendClose(payload []byte) {
	c.once.Do(func() {
		_ = c.ws.WriteControl(websocket.CloseMessage, payload, time.Now().Add(writeWait))
		_ = c.ws.SetReadDeadline(time.Now().Add(writeWait))
	})
}

func (c *Client) Close() {
	c.Session.Close(nil)
}

func (c *Client) Abort() {
	c.ws.Close()
}

func (c *Client) CloseWith(code int, reason string) {
	c.sendClose(websocket.FormatCloseMessage(code, reason))
}

var ErrConnectorClosed = errors.New("tunnel connector closed")

type Connector struct {
	cfg    ClientConfig
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	attempt *attempt
	dials   int
}

type attempt struct {
	done   chan struct{}
	client *Client
	err    error
}

func (a *attempt) usable() bool {
	select {
	case <-a.done:
		return a.err == nil && !a.client.Session.Closed()
	default:
		return true
	}
}

func NewConnector(cfg ClientConfig) *Connector {
	ctx, cancel := context.WithCancel(context.Background())
	return &Connector{cfg: cfg, ctx: ctx, cancel: cancel}
}

func (c *Connector) client(ctx context.Context) (*Client, error) {
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return nil, ErrConnectorClosed
	}
	a := c.attempt
	if a == nil || !a.usable() {
		a = &attempt{done: make(chan struct{})}
		c.attempt = a
		c.dials++
		go func() {
			a.client, a.err = Connect(c.ctx, c.cfg)
			if a.err == nil && c.ctx.Err() != nil {
				a.client.Close()
				a.client, a.err = nil, ErrConnectorClosed
			}
			close(a.done)
		}()
	}
	c.mu.Unlock()
	select {
	case <-a.done:
		return a.client, a.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Connector) Open(ctx context.Context) (*Stream, error) {
	cl, err := c.client(ctx)
	if err != nil {
		return nil, err
	}
	return cl.Session.Open()
}

func (c *Connector) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	return c.Open(ctx)
}

func (c *Connector) Session(ctx context.Context) (*Session, error) {
	cl, err := c.client(ctx)
	if err != nil {
		return nil, err
	}
	return cl.Session, nil
}

func (c *Connector) Dials() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dials
}

func (c *Connector) Close() {
	c.mu.Lock()
	c.cancel()
	a := c.attempt
	c.mu.Unlock()
	if a == nil {
		return
	}
	<-a.done
	if a.client != nil {
		a.client.Close()
	}
}

func (c *Connector) HTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext:         c.DialContext,
		MaxIdleConnsPerHost: maxStreams,
	}}
}
