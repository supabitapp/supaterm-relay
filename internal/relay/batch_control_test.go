package relay

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type batchPipeResponse struct {
	http.ResponseWriter
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (w batchPipeResponse) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, w.rw, nil
}

func batchSocketPair(t *testing.T) (*websocket.Conn, net.Conn, *batchObservedConn) {
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() { remote.Close(); local.Close() })
	_ = remote.SetDeadline(time.Now().Add(3 * time.Second))
	accepted := make(chan *websocket.Conn, 1)
	errors := make(chan error, 1)
	s := New(Config{})
	go func() {
		reader := bufio.NewReader(local)
		req, err := http.ReadRequest(reader)
		if err != nil {
			errors <- err
			return
		}
		w := batchPipeResponse{httptest.NewRecorder(), local, bufio.NewReadWriter(reader, bufio.NewWriter(local))}
		ws, ok := s.upgrade(w, req, 4096)
		if !ok {
			errors <- fmt.Errorf("upgrade failed")
			return
		}
		accepted <- ws
	}()
	client, _, err := websocket.NewClient(remote, &url.URL{Scheme: "ws", Host: "relay.test"}, nil, 4096, 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	select {
	case ws := <-accepted:
		t.Cleanup(func() { s.forget(ws) })
		c := ws.UnderlyingConn().(*batchConn)
		// Handshake is complete and no I/O is running. Observe the next raw
		// write so the test can contend with a known blocked data flush.
		raw := &batchObservedConn{Conn: c.Conn, started: make(chan struct{})}
		c.Conn = raw
		c.enable()
		_ = remote.SetReadDeadline(time.Now().Add(3 * time.Second))
		return ws, remote, raw
	case err := <-errors:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("upgrade did not finish")
	}
	return nil, nil, nil
}

func waitBatchDeadline(t *testing.T, c *batchConn, want time.Time) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		c.deadlineMu.Lock()
		got := c.deadline
		c.deadlineMu.Unlock()
		if got.Equal(want) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("control writer did not set its deadline")
}

func TestBatchConcurrentGorillaControl(t *testing.T) {
	for _, mode := range []string{"ordered flush", "control timeout", "close"} {
		t.Run(mode, func(t *testing.T) {
			ws, remote, raw := batchSocketPair(t)
			c := ws.UnderlyingConn().(*batchConn)
			_ = ws.SetWriteDeadline(time.Now().Add(time.Hour))
			if err := ws.WriteMessage(websocket.BinaryMessage, []byte("data")); err != nil {
				t.Fatal(err)
			}
			flushed := make(chan error, 1)
			go func() { flushed <- c.flush() }()
			waitForHandler(t, raw.started, "raw data flush")
			deadline := time.Now().Add(2 * time.Hour)
			if mode == "control timeout" {
				deadline = time.Now().Add(100 * time.Millisecond)
			}
			controlled := make(chan error, 1)
			go func() { controlled <- ws.WriteControl(websocket.PingMessage, []byte("ping"), deadline) }()
			waitBatchDeadline(t, c, deadline)
			switch mode {
			case "ordered flush":
				want := []byte{0x82, 4, 'd', 'a', 't', 'a', 0x89, 4, 'p', 'i', 'n', 'g'}
				got := make([]byte, len(want))
				if _, err := io.ReadFull(remote, got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("wire bytes = %x, want %x", got, want)
				}
			case "close":
				closed := make(chan error, 1)
				go func() { closed <- ws.Close() }()
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("close blocked behind data/control writers")
				}
			}
			for name, done := range map[string]<-chan error{"flush": flushed, "control": controlled} {
				select {
				case err := <-done:
					if (err == nil) != (mode == "ordered flush") {
						t.Fatalf("%s ended with %v", name, err)
					}
				case <-time.After(2 * time.Second):
					t.Fatalf("%s remained blocked", name)
				}
			}
		})
	}
}

func TestBatchFlushesDataBeforeBufferedControlHandlers(t *testing.T) {
	for name, opcode := range map[string]byte{
		"close": websocket.CloseMessage, "ping": websocket.PingMessage, "pong": websocket.PongMessage,
	} {
		t.Run(name, func(t *testing.T) {
			ws, remote, _ := batchSocketPair(t)
			input := ws.UnderlyingConn().(*batchConn)
			raw := &batchRecordConn{}
			output := newBatchConn(raw)
			output.enable()
			input.flushBeforeRead = output
			frame := []byte{0x82, 2, 'o', 'k'}
			stopped := fmt.Errorf("control handled")
			handle := func() error {
				if !bytes.Equal(raw.Bytes(), frame) || output.buf != nil {
					t.Error("control handler ran before preceding data was flushed")
				}
				return stopped
			}
			ws.SetPingHandler(func(string) error { return handle() })
			ws.SetPongHandler(func(string) error { return handle() })
			ws.SetCloseHandler(func(int, string) error { return handle() })
			input.flushBeforeControls(ws)
			// Both masked client frames arrive in one socket read. The second
			// NextReader must not need another raw Read to flush the first message.
			packet := []byte{0x82, 0x82, 0, 0, 0, 0, 'o', 'k', 0x80 | opcode, 0x80, 0, 0, 0, 0}
			written := make(chan error, 1)
			go func() { _, err := remote.Write(packet); written <- err }()
			_, reader, err := ws.NextReader()
			if err != nil {
				t.Fatal(err)
			}
			if data, err := io.ReadAll(reader); err != nil || string(data) != "ok" {
				t.Fatalf("first message = %q, %v", data, err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if _, err := output.Write(frame); err != nil {
				t.Fatal(err)
			}
			if _, _, err := ws.NextReader(); err != stopped {
				t.Fatalf("control handler result = %v", err)
			}
			output.Close()
		})
	}
}

type batchPartialConn struct {
	batchRecordConn
}

func (c *batchPartialConn) Write(b []byte) (int, error) {
	c.writes++
	n := min(3, len(b))
	c.Buffer.Write(b[:n])
	return n, c.err
}

func TestBatchPartialWriteFailureDoesNotReplayBytes(t *testing.T) {
	failure := fmt.Errorf("partial write failed")
	raw := &batchPartialConn{batchRecordConn: batchRecordConn{err: failure}}
	c := newBatchConn(raw)
	c.enable()
	frame := []byte{0x82, 4, 'd', 'a', 't', 'a'}
	if _, err := c.Write(frame); err != nil {
		t.Fatal(err)
	}
	if err := c.flush(); err != failure {
		t.Fatalf("flush = %v", err)
	}
	if _, err := c.Write([]byte{0x89, 0}); err != failure {
		t.Fatalf("control after failure = %v", err)
	}
	if err := c.flush(); err != failure {
		t.Fatalf("repeat flush = %v", err)
	}
	if raw.writes != 1 || !bytes.Equal(raw.Bytes(), frame[:3]) {
		t.Fatalf("replayed or appended bytes after failure: %x", raw.Bytes())
	}
	if err := c.Close(); err != nil || c.buf != nil {
		t.Fatalf("close = %v, buffer retained = %v", err, c.buf != nil)
	}
}
