package relay

import (
	"bufio"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const batchBufferSize = 4096

var batchBuffers = sync.Pool{New: func() any {
	return bufio.NewWriterSize(nil, batchBufferSize)
}}

// batchConn combines already-available WebSocket frames into socket writes.
// Its reader flushes the opposite socket before requesting more input, so no
// timer or additional message queue is needed to flush an idle stream.
type batchConn struct {
	net.Conn
	mu     sync.Mutex
	buf    *bufio.Writer
	batch  bool
	writer batchWriter
	closed atomic.Bool

	// Set and used only by the connection's reader after pairing.
	flushBeforeRead *batchConn

	deadlineMu    sync.Mutex
	deadline      time.Time
	writing       bool
	deadlineSet   bool
	writeDeadline time.Time
}

func newBatchConn(conn net.Conn) *batchConn {
	c := &batchConn{Conn: conn}
	c.writer.conn = c
	return c
}

type batchWriter struct{ conn *batchConn }

func (w *batchWriter) Write(b []byte) (int, error) {
	c := w.conn
	c.deadlineMu.Lock()
	var err error
	if !c.deadlineSet || !c.writeDeadline.Equal(c.deadline) {
		err = c.Conn.SetWriteDeadline(c.deadline)
		if err == nil {
			c.writeDeadline, c.deadlineSet = c.deadline, true
		}
	}
	c.writing = true
	c.deadlineMu.Unlock()
	var n int
	if err == nil {
		n, err = c.Conn.Write(b)
	}
	c.deadlineMu.Lock()
	c.writing = false
	c.deadlineMu.Unlock()
	return n, err
}

func (c *batchConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.deadline = t
	// A source-driven flush runs outside Gorilla's write lock. A concurrent
	// control writer may shorten its timeout, but cannot keep a stalled data
	// write alive by extending it on every heartbeat.
	if c.writing && !c.writeDeadline.IsZero() && (t.IsZero() || t.After(c.writeDeadline)) {
		return nil
	}
	err := c.Conn.SetWriteDeadline(t)
	if err == nil {
		c.writeDeadline, c.deadlineSet = t, true
	}
	return err
}

func (c *batchConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *batchConn) enable() {
	c.mu.Lock()
	c.batch = true
	c.mu.Unlock()
}

func (c *batchConn) flushOutput() error {
	if out := c.flushBeforeRead; out != nil {
		if err := out.flush(); err != nil {
			return &forwardWriteError{err}
		}
	}
	return nil
}

func (c *batchConn) Read(b []byte) (int, error) {
	if err := c.flushOutput(); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

// Control frames may already be in Gorilla's read buffer. Flush preceding data
// before invoking handlers that can block or start connection teardown.
func (c *batchConn) flushBeforeControls(ws *websocket.Conn) {
	wrap := func(handler func(string) error) func(string) error {
		return func(data string) error {
			if err := c.flushOutput(); err != nil {
				return err
			}
			return handler(data)
		}
	}
	ws.SetPingHandler(wrap(ws.PingHandler()))
	ws.SetPongHandler(wrap(ws.PongHandler()))
	closeHandler := ws.CloseHandler()
	ws.SetCloseHandler(func(code int, text string) error {
		if err := c.flushOutput(); err != nil {
			return err
		}
		return closeHandler(code, text)
	})
}

func (c *batchConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if !c.batch || c.buf == nil && len(b) >= batchBufferSize {
		return c.writer.Write(b)
	}
	if c.buf == nil {
		c.buf = batchBuffers.Get().(*bufio.Writer)
		c.buf.Reset(&c.writer)
	}
	n, err := c.buf.Write(b)
	// Gorilla writes control frames in one call. A payload continuation may
	// happen to match too; flushing it early does not change the bytes.
	if err == nil && len(b) > 0 && b[0]&8 != 0 {
		err = c.buf.Flush()
	}
	if err == nil && c.buf.Buffered() == 0 {
		c.release()
	}
	return n, err
}

// release requires c.mu. Idle connections do not retain a batch buffer.
func (c *batchConn) release() {
	c.buf.Reset(nil)
	batchBuffers.Put(c.buf)
	c.buf = nil
}

func (c *batchConn) flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	if c.buf == nil {
		return nil
	}
	if err := c.buf.Flush(); err != nil {
		return err
	}
	c.release()
	return nil
}

func (c *batchConn) Close() error {
	c.closed.Store(true)
	// Interrupt an outstanding flush before waiting to reclaim its buffer.
	err := c.Conn.Close()
	c.mu.Lock()
	if c.buf != nil {
		c.release()
	}
	c.mu.Unlock()
	return err
}

type forwardWriteError struct{ error }

func (e *forwardWriteError) Unwrap() error { return e.error }

type batchResponseWriter struct{ http.ResponseWriter }

func (w batchResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	return newBatchConn(conn), rw, nil
}
