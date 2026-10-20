package relay

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestHTTPTimeoutsReleaseConnections(t *testing.T) {
	for _, listener := range []string{"public", "private"} {
		for _, request := range []struct {
			name      string
			body      string
			keepAlive bool
		}{
			{"incomplete body", "GET /healthz HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n", false},
			{"idle keepalive", "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n", true},
		} {
			t.Run(listener+"/"+request.name, func(t *testing.T) {
				cfg, err := LoadConfig(env(nil))
				if err != nil {
					t.Fatal(err)
				}
				relay := New(cfg)
				server := relay.http
				if listener == "private" {
					server = relay.private
				}
				closed := make(chan struct{}, 1)
				server.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateClosed {
						closed <- struct{}{}
					}
				}
				address := serveHTTPWithShortTimeouts(t, server)
				conn, err := net.Dial("tcp", address)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if _, err := io.WriteString(conn, request.body); err != nil {
					t.Fatal(err)
				}
				if request.keepAlive {
					_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
					response, err := http.ReadResponse(bufio.NewReader(conn), nil)
					if err != nil {
						t.Fatal(err)
					}
					_, err = io.Copy(io.Discard, response.Body)
					_ = response.Body.Close()
					if err != nil || response.StatusCode != http.StatusOK {
						t.Fatalf("health response: %d, %v", response.StatusCode, err)
					}
				}
				select {
				case <-closed:
				case <-time.After(3 * time.Second):
					t.Fatal("HTTP timeout did not release the connection")
				}
			})
		}
	}
}

func TestHTTPTimeoutsDoNotExpireWebSockets(t *testing.T) {
	cfg, err := LoadConfig(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	relay := New(cfg)
	address := serveHTTPWithShortTimeouts(t, relay.http)
	host := registerHost(t, "ws://"+address)
	client, peer := openPair(t, host)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for range 4 {
		<-ticker.C
		expectPairMessage(t, client, peer)
		expectPairMessage(t, peer, client)
	}
	if err := client.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolServesUnderAnyPathPrefix(t *testing.T) {
	cfg, err := LoadConfig(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg)
	listener := httptest.NewServer(s.http.Handler)
	t.Cleanup(listener.Close)
	t.Cleanup(func() { closeLifecycleSockets(s) })
	base := "ws" + strings.TrimPrefix(listener.URL, "http")
	for _, prefix := range []string{"", "/tunnel", "/relay/v2", "/dashboard", "/a/../b", "/tun%2Fnel"} {
		h := registerHost(t, base+prefix)
		client, host := openPair(t, h)
		expectPairMessage(t, client, host)
	}
	h := registerHost(t, base+"/tunnel")
	h.Base = base
	client, host := openPair(t, h)
	expectPairMessage(t, client, host)

	for _, path := range []string{"/tunnel/v1/other", "/tunnelv1/connect", "/tunnel/metrics", "/tunnel/healthz", "/tunnel/dashboard/"} {
		resp, err := http.Get(listener.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: %s, want 404", path, resp.Status)
		}
	}
}

func serveHTTPWithShortTimeouts(t *testing.T, server *http.Server) string {
	t.Helper()
	for _, timeout := range []*time.Duration{&server.ReadHeaderTimeout, &server.ReadTimeout, &server.WriteTimeout, &server.IdleTimeout} {
		if *timeout > 0 {
			*timeout = 50 * time.Millisecond
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		<-stopped
	})
	return listener.Addr().String()
}
