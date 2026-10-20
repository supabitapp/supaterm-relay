package supaterm

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type wire struct {
	mu      sync.Mutex
	cond    *sync.Cond
	queue   [][]byte
	paused  bool
	closed  bool
	largest int
	records int
}

func newWire(deliver func([]byte)) *wire {
	w := &wire{}
	w.cond = sync.NewCond(&w.mu)
	go func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		for {
			for !w.closed && (len(w.queue) == 0 || w.paused) {
				w.cond.Wait()
			}
			if w.closed {
				return
			}
			next := w.queue[0]
			w.queue = w.queue[1:]
			w.mu.Unlock()
			deliver(next)
			w.mu.Lock()
		}
	}()
	return w
}

func (w *wire) send(b []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("socket closed")
	}
	if w.paused {
		return nil
	}
	w.largest = max(w.largest, len(b))
	w.records++
	w.queue = append(w.queue, b)
	w.cond.Broadcast()
	return nil
}

func (w *wire) set(paused, closed bool) {
	w.mu.Lock()
	w.paused, w.closed = paused, closed
	w.cond.Broadcast()
	w.mu.Unlock()
}

func (w *wire) stats() (largest, records int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.largest, w.records
}

type memPair struct {
	client, host     *Session
	toHost, toClient *wire
	accepted         chan *Stream
}

func newMemPair(t *testing.T, keepAlive time.Duration) *memPair {
	t.Helper()
	identity := ed25519.NewKeyFromSeed(randomBytes(32))
	hs, err := NewClientHandshake(identity.Public().(ed25519.PublicKey), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	welcome, hostCipher, err := AcceptClientHandshake(hs.Hello, identity, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientCipher, err := hs.Finish(welcome)
	if err != nil {
		t.Fatal(err)
	}
	p := &memPair{accepted: make(chan *Stream, maxStreams*2)}
	ready := make(chan struct{})
	p.toHost = newWire(func(b []byte) { <-ready; p.host.Receive(b) })
	p.toClient = newWire(func(b []byte) { <-ready; p.client.Receive(b) })
	p.client = NewSession(SessionConfig{Cipher: clientCipher, Initiator: true, Send: p.toHost.send, KeepAlive: keepAlive})
	p.host = NewSession(SessionConfig{Cipher: hostCipher, Send: p.toClient.send, KeepAlive: keepAlive, OnStream: func(st *Stream) { p.accepted <- st }})
	close(ready)
	t.Cleanup(func() {
		p.client.Close(nil)
		p.host.Close(nil)
		p.toHost.set(false, true)
		p.toClient.set(false, true)
	})
	return p
}

func (p *memPair) next(t *testing.T) *Stream {
	t.Helper()
	select {
	case st := <-p.accepted:
		return st
	case <-time.After(5 * time.Second):
		t.Fatal("no stream accepted")
		return nil
	}
}

func (p *memPair) forge(plain []byte) {
	p.client.mu.Lock()
	record := p.client.cfg.Cipher.Seal(plain)
	p.client.mu.Unlock()
	p.host.Receive(record)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func eventually(t *testing.T, desc string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", desc)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func buffered(st *Stream) int {
	st.s.mu.Lock()
	defer st.s.mu.Unlock()
	return st.unconsumed
}

func TestTunnelEndsAFullRecordWithinTheWireLimit(t *testing.T) {
	p := newMemPair(t, 0)
	st, err := p.client.Open()
	if err != nil {
		t.Fatal(err)
	}
	payload := randomBytes(MaxPlainBytes - 18)
	if _, err := st.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = st.CloseWrite()
	remote := p.next(t)
	got, err := io.ReadAll(remote)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("read %d bytes: %v", len(got), err)
	}
	_ = remote.CloseWrite()
	if rest, err := io.ReadAll(st); err != nil || len(rest) != 0 {
		t.Fatalf("client read %d bytes: %v", len(rest), err)
	}
	eventually(t, "both streams released", func() bool { return p.client.StreamCount() == 0 && p.host.StreamCount() == 0 })
	if largest, _ := p.toHost.stats(); largest > MaxRecordBytes {
		t.Fatalf("record of %d bytes exceeds %d", largest, MaxRecordBytes)
	}
	if p.host.Closed() {
		t.Fatal("host session closed")
	}
}

func TestTunnelStreamsALargeUploadBesideAnotherStream(t *testing.T) {
	p := newMemPair(t, 0)
	a, _ := p.client.Open()
	b, _ := p.client.Open()
	payload := randomBytes(20 << 20)
	sums := make(chan [32]byte, 2)
	for _, remote := range []*Stream{p.next(t), p.next(t)} {
		go func() {
			data, _ := io.ReadAll(remote)
			sums <- sha256.Sum256(data)
		}()
	}
	small := make([]byte, 320)
	go func() {
		for i := range small {
			_, _ = b.Write([]byte{byte(i)})
		}
		_ = b.CloseWrite()
	}()
	if _, err := a.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = a.CloseWrite()
	for i := range small {
		small[i] = byte(i)
	}
	want := map[[32]byte]bool{sha256.Sum256(payload): true, sha256.Sum256(small): true}
	for range 2 {
		select {
		case sum := <-sums:
			if !want[sum] {
				t.Fatal("stream contents differ")
			}
			delete(want, sum)
		case <-time.After(30 * time.Second):
			t.Fatal("upload did not finish")
		}
	}
	if largest, _ := p.toHost.stats(); largest > MaxRecordBytes {
		t.Fatalf("record of %d bytes exceeds %d", largest, MaxRecordBytes)
	}
}

func TestTunnelStallsAtASlowReaderAndResumes(t *testing.T) {
	p := newMemPair(t, 0)
	st, _ := p.client.Open()
	go func() { _, _ = st.Write(make([]byte, streamWindow+1024)) }()
	remote := p.next(t)
	eventually(t, "the stream window to fill", func() bool { return buffered(remote) == streamWindow })
	time.Sleep(20 * time.Millisecond)
	if n := buffered(remote); n != streamWindow {
		t.Fatalf("receiver holds %d bytes beyond its %d byte window", n, streamWindow)
	}
	got, err := io.ReadFull(remote, make([]byte, streamWindow+1024))
	if err != nil || got != streamWindow+1024 {
		t.Fatalf("read %d: %v", got, err)
	}
}

func TestTunnelBoundsASessionWhenManyReadersStall(t *testing.T) {
	p := newMemPair(t, 0)
	var streams []*Stream
	for range 8 {
		st, _ := p.client.Open()
		go func() { _, _ = st.Write(make([]byte, streamWindow)) }()
		streams = append(streams, p.next(t))
	}
	total := func() int {
		n := 0
		for _, st := range streams {
			n += buffered(st)
		}
		return n
	}
	eventually(t, "stalled streams to hold data", func() bool { return total() > streamWindow })
	time.Sleep(50 * time.Millisecond)
	if n := total(); n > sessionWindow {
		t.Fatalf("receiver holds %d bytes beyond the %d byte session window", n, sessionWindow)
	}
	if p.host.Closed() || p.client.Closed() {
		t.Fatal("session closed")
	}
}

func TestTunnelKeepsAConsumingStreamMovingBesideStalledStreams(t *testing.T) {
	p := newMemPair(t, 0)
	for range 3 {
		st, _ := p.client.Open()
		go func() { _, _ = st.Write(make([]byte, streamWindow)) }()
		p.next(t)
	}
	active, _ := p.client.Open()
	if active.ID() != 7 {
		t.Fatalf("stream id %d, want 7", active.ID())
	}
	remote := p.next(t)
	done := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(io.Discard, remote)
		done <- n
	}()
	for range 16 {
		if _, err := active.Write(make([]byte, 1<<20)); err != nil {
			t.Fatal(err)
		}
	}
	_ = active.CloseWrite()
	select {
	case n := <-done:
		if n != 16<<20 {
			t.Fatalf("delivered %d bytes", n)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("active stream stalled behind stalled readers")
	}
}

func TestTunnelAnswersKeepalivesAndClosesWhenThePeerGoesSilent(t *testing.T) {
	p := newMemPair(t, 20*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	if p.client.Closed() || p.host.Closed() {
		t.Fatalf("idle session closed: %v %v", p.client.Err(), p.host.Err())
	}
	if _, records := p.toHost.stats(); records == 0 {
		t.Fatal("client sent no keepalive")
	}
	p.toClient.set(true, false)
	p.toHost.set(true, false)
	eventually(t, "silent sessions to close", func() bool { return p.client.Closed() && p.host.Closed() })
	if !errors.Is(p.client.Err(), ErrTimedOut) || !errors.Is(p.host.Err(), ErrTimedOut) {
		t.Fatalf("closed with %v and %v", p.client.Err(), p.host.Err())
	}
}

func TestTunnelRejectsAPeerThatBypassesStreamCredit(t *testing.T) {
	p := newMemPair(t, 0)
	_, _ = p.client.Open()
	p.next(t)
	data := frame(frameData, 1, make([]byte, MaxPlainBytes-headerBytes))
	for i := 0; i < 66 && !p.host.Closed(); i++ {
		p.forge(data)
	}
	if !p.host.Closed() {
		t.Fatal("host accepted data beyond the stream window")
	}
}

func TestTunnelRejectsStreamReuseAndMalformedFrames(t *testing.T) {
	for _, f := range []struct {
		typ    byte
		id     uint32
		length int
	}{
		{frameOpen, 1, 0},
		{frameFin, 1, 1},
		{frameRst, 1, 1},
		{frameWindow, 0, 4},
		{framePing, 1, 0},
		{framePong, 0, 1},
		{frameData, 1, 0},
		{frameData, 2, 1},
		{frameData, 9, 1},
		{frameWindow, 1, 3},
		{9, 1, 0},
	} {
		p := newMemPair(t, 0)
		_, _ = p.client.Open()
		p.next(t)
		p.forge(frame(f.typ, f.id, make([]byte, f.length)))
		if !p.host.Closed() {
			t.Errorf("host accepted frame type %d id %d length %d", f.typ, f.id, f.length)
		}
	}
}

func TestTunnelRefusesStreamsBeyondItsLimit(t *testing.T) {
	p := newMemPair(t, 0)
	var open []*Stream
	for range maxStreams {
		st, err := p.client.Open()
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, st)
	}
	if _, err := p.client.Open(); err == nil {
		t.Fatal("opened a stream beyond the limit")
	}
	for range maxStreams {
		p.next(t)
	}
	_ = open[0].Close()
	eventually(t, "a stream slot to free", func() bool { return p.client.StreamCount() < maxStreams })
	if _, err := p.client.Open(); err != nil {
		t.Fatal(err)
	}
}

func TestTunnelFailsPendingWritersWhenTheSessionCloses(t *testing.T) {
	p := newMemPair(t, 0)
	p.toHost.set(true, false)
	st, _ := p.client.Open()
	var failed atomic.Value
	go func() {
		_, err := st.Write(make([]byte, 4*streamWindow))
		failed.Store(err)
	}()
	eventually(t, "the writer to block", func() bool {
		st.s.mu.Lock()
		defer st.s.mu.Unlock()
		return st.pendingBytes > 0 && st.sendCredit == 0
	})
	cause := errors.New("disconnected")
	p.client.Close(cause)
	eventually(t, "the writer to fail", func() bool { return failed.Load() != nil })
	if err, _ := failed.Load().(error); !errors.Is(err, cause) {
		t.Fatalf("writer failed with %v", err)
	}
	if _, err := st.Read(make([]byte, 1)); !errors.Is(err, cause) {
		t.Fatalf("read after close: %v", err)
	}
	if _, err := p.client.Open(); err == nil {
		t.Fatal("opened a stream on a closed session")
	}
}
