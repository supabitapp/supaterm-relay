package relay

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type batchRecordConn struct {
	net.Conn
	bytes.Buffer
	writes        int
	deadlineCalls int
	read          func([]byte) (int, error)
	err           error
}

func (c *batchRecordConn) Write(b []byte) (int, error) {
	c.writes++
	if c.err != nil {
		return 0, c.err
	}
	return c.Buffer.Write(b)
}

func (c *batchRecordConn) Read(b []byte) (int, error) {
	if c.read != nil {
		return c.read(b)
	}
	return 0, io.EOF
}

func (c *batchRecordConn) SetWriteDeadline(time.Time) error {
	c.deadlineCalls++
	return nil
}

func (*batchRecordConn) Close() error { return nil }

func TestBatchWritesPreserveFramesAndReleaseBuffer(t *testing.T) {
	raw := &batchRecordConn{}
	c := newBatchConn(raw)
	c.enable()
	frame := []byte{0x82, 3, 'o', 'n', 'e'}
	want := bytes.Repeat(frame, 8)
	for range 8 {
		if n, err := c.Write(frame); n != len(frame) || err != nil {
			t.Fatalf("write = %d, %v", n, err)
		}
	}
	if raw.writes != 0 || c.buf == nil || c.buf.Buffered() != len(want) {
		t.Fatal("frames were not batched")
	}
	if err := c.flush(); err != nil {
		t.Fatal(err)
	}
	if raw.writes != 1 || !bytes.Equal(raw.Bytes(), want) || c.buf != nil {
		t.Fatal("flush changed frames, failed to coalesce writes, or retained its buffer")
	}
	if err := c.flush(); err != nil || raw.writes != 1 {
		t.Fatal("empty flush wrote to the socket")
	}
}

func TestBatchHandshakeAndControlWritesFlushImmediately(t *testing.T) {
	for name, opcode := range map[string]byte{
		"close": websocket.CloseMessage, "ping": websocket.PingMessage, "pong": websocket.PongMessage,
	} {
		t.Run(name, func(t *testing.T) {
			raw := &batchRecordConn{}
			c := newBatchConn(raw)
			handshake := []byte("HTTP/1.1 101 Switching Protocols\r\n\r\n")
			if _, err := c.Write(handshake); err != nil || raw.writes != 1 || c.buf != nil {
				t.Fatal("handshake was buffered")
			}
			c.enable()
			data := []byte{0x82, 1, 'x'}
			control := []byte{0x80 | opcode, 0}
			if _, err := c.Write(data); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Write(control); err != nil {
				t.Fatal(err)
			}
			want := append(append(append([]byte{}, handshake...), data...), control...)
			if raw.writes != 2 || !bytes.Equal(raw.Bytes(), want) || c.buf != nil {
				t.Fatal("control write did not flush preceding data in order")
			}
		})
	}
}

func TestBatchReadFlushesBeforeRequestingInput(t *testing.T) {
	output := &batchRecordConn{}
	out := newBatchConn(output)
	out.enable()
	frame := []byte{0x82, 1, 'x'}
	if _, err := out.Write(frame); err != nil {
		t.Fatal(err)
	}
	input := &batchRecordConn{read: func(b []byte) (int, error) {
		if !bytes.Equal(output.Bytes(), frame) || out.buf != nil {
			t.Fatal("requested more input before flushing and releasing output")
		}
		return copy(b, "next"), nil
	}}
	in := newBatchConn(input)
	in.flushBeforeRead = out
	buf := make([]byte, 4)
	if n, err := in.Read(buf); n != 4 || err != nil || string(buf) != "next" {
		t.Fatalf("read = %d, %v, %q", n, err, buf)
	}
}

func TestBatchFlushFailureIsADestinationFailure(t *testing.T) {
	failure := errors.New("destination failed")
	out := newBatchConn(&batchRecordConn{err: failure})
	out.enable()
	defer out.Close()
	if _, err := out.Write([]byte{0x82, 0}); err != nil {
		t.Fatal(err)
	}
	in := newBatchConn(&batchRecordConn{read: func([]byte) (int, error) {
		t.Fatal("read input after output failed")
		return 0, nil
	}})
	in.flushBeforeRead = out
	_, err := in.Read(make([]byte, 1))
	var writeErr *forwardWriteError
	if !errors.As(err, &writeErr) || !errors.Is(err, failure) {
		t.Fatalf("lost destination failure: %v", err)
	}
	if cause := (&peer{}).closeCause(err); cause.code != websocket.CloseTryAgainLater || cause.reason != "peer write timeout" {
		t.Fatalf("incorrect close cause: %+v", cause)
	}
}

func TestBatchLargeWritesReuseInstalledDeadline(t *testing.T) {
	raw := &batchRecordConn{}
	c := newBatchConn(raw)
	c.enable()
	deadline := time.Now().Add(time.Hour)
	if err := c.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	frame := bytes.Repeat([]byte{0x82}, 2*batchBufferSize)
	for range 3 {
		if n, err := c.Write(frame); n != len(frame) || err != nil {
			t.Fatalf("large write = %d, %v", n, err)
		}
		if c.buf != nil {
			t.Fatal("large write retained a batch buffer")
		}
	}
	if raw.writes != 3 || raw.deadlineCalls != 1 {
		t.Fatalf("large writes=%d deadline updates=%d, want 3 and 1", raw.writes, raw.deadlineCalls)
	}
}

func TestBatchLargeWritesAndPayloadPrefixesPreserveBytes(t *testing.T) {
	for _, prefix := range []byte{0, 8, 0x82, 0x89, 0xff} {
		raw := &batchRecordConn{}
		c := newBatchConn(raw)
		c.enable()
		header := []byte{0x02, 126, 0, 1}
		payload := bytes.Repeat([]byte{prefix}, 5*batchBufferSize+7)
		for _, b := range [][]byte{header, payload} {
			if n, err := c.Write(b); n != len(b) || err != nil {
				t.Fatalf("write = %d, %v", n, err)
			}
			if c.buf != nil && c.buf.Buffered() > batchBufferSize {
				t.Fatal("batch grew beyond its fixed capacity")
			}
		}
		if err := c.flush(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw.Bytes(), append(header, payload...)) || c.buf != nil {
			t.Fatal("payload prefix changed bytes or retained storage")
		}
	}
}

type batchObservedConn struct {
	net.Conn
	started  chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
}

func (c *batchObservedConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *batchObservedConn) lastDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline
}

func (c *batchObservedConn) Write(b []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(b)
}

func blockedBatch(t *testing.T, deadline time.Time) (*batchConn, <-chan error) {
	t.Helper()
	local, remote := net.Pipe()
	raw := &batchObservedConn{Conn: local, started: make(chan struct{})}
	c := newBatchConn(raw)
	t.Cleanup(func() {
		// Release any blocked write even if the assertion under test fails.
		remote.Close()
		c.Close()
	})
	c.enable()
	if err := c.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{0x82, 1, 'x'}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.flush() }()
	select {
	case <-raw.started:
	case <-time.After(3 * time.Second):
		t.Fatal("flush did not start")
	}
	return c, done
}

func expectBatchTimeout(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("flush = %v, want timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("flush outlived its deadline")
	}
}

func TestBatchControlCannotExtendActiveFlushDeadline(t *testing.T) {
	for _, clear := range []bool{false, true} {
		name := "extend"
		if clear {
			name = "clear"
		}
		t.Run(name, func(t *testing.T) {
			c, done := blockedBatch(t, time.Now().Add(150*time.Millisecond))
			later := time.Now().Add(time.Hour)
			if clear {
				later = time.Time{}
			}
			if err := c.SetWriteDeadline(later); err != nil {
				t.Fatal(err)
			}
			expectBatchTimeout(t, done)
		})
	}
}

func TestBatchDefersLaterDeadlineUntilNextWrite(t *testing.T) {
	for _, clear := range []bool{false, true} {
		name := "extend"
		if clear {
			name = "clear"
		}
		t.Run(name, func(t *testing.T) {
			local, remote := net.Pipe()
			raw := &batchObservedConn{Conn: local, started: make(chan struct{})}
			c := newBatchConn(raw)
			t.Cleanup(func() { remote.Close(); c.Close() })
			_ = remote.SetReadDeadline(time.Now().Add(3 * time.Second))
			c.enable()
			first := time.Now().Add(time.Hour)
			if err := c.SetWriteDeadline(first); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Write([]byte{0x82, 0}); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- c.flush() }()
			select {
			case <-raw.started:
			case <-time.After(3 * time.Second):
				t.Fatal("flush did not start")
			}
			later := first.Add(time.Hour)
			if clear {
				later = time.Time{}
			}
			if err := c.SetWriteDeadline(later); err != nil {
				t.Fatal(err)
			}
			if got := raw.lastDeadline(); !got.Equal(first) {
				t.Fatalf("active deadline = %v, want %v", got, first)
			}
			if _, err := io.ReadFull(remote, make([]byte, 2)); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			go func() {
				_, err := c.Write([]byte{0x89, 0})
				done <- err
			}()
			if _, err := io.ReadFull(remote, make([]byte, 2)); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if got := raw.lastDeadline(); !got.Equal(later) {
				t.Fatalf("next deadline = %v, want %v", got, later)
			}
		})
	}
}

func TestBatchControlCanShortenActiveFlushDeadline(t *testing.T) {
	c, done := blockedBatch(t, time.Now().Add(time.Hour))
	if err := c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	expectBatchTimeout(t, done)
}

func TestBatchCloseInterruptsFlushBeforeReclaimingBuffer(t *testing.T) {
	c, flushed := blockedBatch(t, time.Now().Add(time.Hour))
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close waited for the flush instead of interrupting it")
	}
	select {
	case err := <-flushed:
		if err == nil {
			t.Fatal("closed flush succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("flush remained blocked after close")
	}
	if c.buf != nil {
		t.Fatal("closed connection retained a batch buffer")
	}
	if _, err := c.Write([]byte{0x82, 0}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close = %v", err)
	}
}
