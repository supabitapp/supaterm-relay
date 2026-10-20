package supaterm

import (
	"bytes"
	"io"
	"net"
	"os"
	"time"
)

func (st *Stream) Read(b []byte) (int, error) {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(st.inbox) == 0 {
		switch {
		case st.err != nil:
			return 0, st.err
		case st.remoteEnded || st.closed:
			return 0, io.EOF
		case passed(st.readDeadline):
			return 0, os.ErrDeadlineExceeded
		}
		st.cond.Wait()
	}
	n := copy(b, st.inbox[0])
	if n == len(st.inbox[0]) {
		st.inbox = st.inbox[1:]
	} else {
		st.inbox[0] = st.inbox[0][n:]
	}
	st.consumed(n)
	return n, nil
}

func (st *Stream) Write(b []byte) (int, error) {
	written := 0
	for written < len(b) {
		chunk := b[written:min(len(b), written+maxWriteChunk)]
		if err := st.writeChunk(bytes.Clone(chunk)); err != nil {
			return written, err
		}
		written += len(chunk)
	}
	return written, nil
}

func (st *Stream) writeChunk(chunk []byte) error {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	sent := false
	var result error
	err := st.write(chunk, func(err error) {
		sent, result = true, err
		st.cond.Broadcast()
	})
	if err != nil {
		return err
	}
	for !sent {
		if passed(st.writeDeadline) {
			st.reset()
			return os.ErrDeadlineExceeded
		}
		st.cond.Wait()
	}
	return result
}

func (st *Stream) CloseWrite() error {
	s := st.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.closed || st.localEnded {
		return nil
	}
	st.localEnded = true
	s.markReady(st)
	return nil
}

func (st *Stream) Close() error {
	st.s.mu.Lock()
	defer st.s.mu.Unlock()
	st.reset()
	return nil
}

func (st *Stream) LocalAddr() net.Addr  { return tunnelAddr{} }
func (st *Stream) RemoteAddr() net.Addr { return tunnelAddr{} }

func (st *Stream) SetDeadline(t time.Time) error {
	_ = st.SetReadDeadline(t)
	return st.SetWriteDeadline(t)
}

func (st *Stream) SetReadDeadline(t time.Time) error {
	st.s.mu.Lock()
	defer st.s.mu.Unlock()
	st.readDeadline = t
	st.readTimer = st.wakeAt(st.readTimer, t)
	return nil
}

func (st *Stream) SetWriteDeadline(t time.Time) error {
	st.s.mu.Lock()
	defer st.s.mu.Unlock()
	st.writeDeadline = t
	st.writeTimer = st.wakeAt(st.writeTimer, t)
	return nil
}

func (st *Stream) wakeAt(timer *time.Timer, t time.Time) *time.Timer {
	if timer != nil {
		timer.Stop()
		timer = nil
	}
	if !t.IsZero() {
		timer = time.AfterFunc(time.Until(t), func() {
			st.s.mu.Lock()
			st.cond.Broadcast()
			st.s.mu.Unlock()
		})
	}
	st.cond.Broadcast()
	return timer
}

func passed(deadline time.Time) bool {
	return !deadline.IsZero() && !time.Now().Before(deadline)
}

type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "relay" }
func (tunnelAddr) String() string  { return "relay" }
