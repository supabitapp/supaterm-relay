//go:build unix

package relay

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func batchTCPPair(t *testing.T) (*batchConn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()
	peer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	c := newBatchConn(server)
	t.Cleanup(func() {
		_ = c.Close()
		_ = peer.Close()
	})
	return c, peer
}

func TestBatchReadsCombineAvailableInput(t *testing.T) {
	c, peer := batchTCPPair(t)
	want := bytes.Repeat([]byte("0123456789"), 300)
	if _, err := peer.Write(want); err != nil {
		t.Fatal(err)
	}
	var got []byte
	combined := false
	buf := make([]byte, 1024)
	for len(got) < len(want) {
		n, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, buf[:n]...)
		combined = combined || len(c.unread) > 0
	}
	if !bytes.Equal(got, want) {
		t.Fatal("pooled reads changed the input")
	}
	if !combined {
		t.Fatal("small reads did not share one socket read")
	}
	if c.readBuf != nil || c.unread != nil {
		t.Fatal("drained reader retained its buffer")
	}
}

func TestBatchBlockedReadHoldsNoBuffer(t *testing.T) {
	c, peer := batchTCPPair(t)
	if err := c.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	_, err := c.Read(buf)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("read error = %v, want timeout", err)
	}
	if c.readBuf != nil {
		t.Fatal("timed-out reader retained a buffer")
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Read(buf); n != 1 || err != nil || buf[0] != 'x' || c.readBuf != nil {
		t.Fatalf("read = %d, %v; buffer retained = %t", n, err, c.readBuf != nil)
	}
}

func TestBatchLargeReadsBypassPool(t *testing.T) {
	c, peer := batchTCPPair(t)
	if _, err := peer.Write(make([]byte, 2*readBatchSize)); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Read(make([]byte, readBatchSize)); n == 0 || err != nil || c.readBuf != nil {
		t.Fatalf("read = %d, %v; buffer taken = %t", n, err, c.readBuf != nil)
	}
}

func TestBatchReadReportsEOF(t *testing.T) {
	c, peer := batchTCPPair(t)
	if _, err := peer.Write([]byte("last")); err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "last" || c.readBuf != nil {
		t.Fatalf("read %q, %v; buffer retained = %t", got, err, c.readBuf != nil)
	}
}

func TestBatchReleaseReadReturnsUnreadInput(t *testing.T) {
	c, peer := batchTCPPair(t)
	if _, err := peer.Write(make([]byte, 3000)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	for c.readBuf == nil {
		if _, err := c.Read(buf); err != nil {
			t.Fatal(err)
		}
	}
	c.releaseRead()
	if c.readBuf != nil || c.unread != nil {
		t.Fatal("released reader kept its buffer")
	}
}

func TestStoppedForwarderReleasesUnreadInput(t *testing.T) {
	cfg, err := LoadConfig(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg)
	listener := httptest.NewServer(s.http.Handler)
	t.Cleanup(listener.Close)
	client, _ := openPair(t, registerHost(t, "ws"+strings.TrimPrefix(listener.URL, "http")))
	s.mu.Lock()
	var input *batchConn
	var ws *websocket.Conn
	for _, p := range s.pairs {
		ws = p.client.ws
		input = ws.UnderlyingConn().(*batchConn)
	}
	s.mu.Unlock()
	// An unmasked client frame stops the forwarder while the rest of this
	// write is still buffered.
	wire := append([]byte{0x82, 0}, make([]byte, 3000)...)
	if _, err := client.UnderlyingConn().Write(wire); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		_, open := s.conns[ws]
		s.mu.Unlock()
		if !open {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("forwarder did not stop")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if input.readBuf != nil {
		t.Fatal("stopped forwarder kept its read buffer")
	}
}
