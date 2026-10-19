package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gobwas/ws"
	"golang.org/x/sys/unix"
)

var (
	addr       = flag.String("addr", "127.0.0.1:8080", "listen address")
	mode       = flag.String("mode", "epoll", "goroutine or epoll")
	heartbeat  = flag.Duration("heartbeat", 15*time.Second, "ping interval")
	maxMessage = flag.Int64("max-message", 32<<20, "largest message")
	debug      = os.Getenv("SPIKE_DEBUG") == "1"
)

const (
	readBufferSize  = 4096
	writeBufferSize = 16 * 1024
	deliveryTimeout = 30 * time.Second
	controlTimeout  = 5 * time.Second
)

var (
	errProtocol = errors.New("protocol error")
	errPolicy   = errors.New("policy violation")
	errTooBig   = errors.New("message too big")
	errClosed   = errors.New("peer closed")

	readers = sync.Pool{New: func() any { return bufio.NewReaderSize(nil, readBufferSize) }}
	writers = sync.Pool{New: func() any { b := make([]byte, writeBufferSize); return &b }}

	nextID  atomic.Uint32
	open    atomic.Int64
	pairsMu sync.Mutex
	waiting = map[string]*conn{}
	poll    *poller
)

type conn struct {
	id         uint32
	nc         net.Conn
	raw        syscall.RawConn
	peer       *conn
	wmu        sync.Mutex
	lastSeen   atomic.Int64
	timer      *time.Timer
	closed     atomic.Bool
	fragmented bool
	msgBytes   int64
	peek       [1]byte
}

func main() {
	flag.Parse()
	if *mode == "epoll" {
		var err error
		if poll, err = newPoller(); err != nil {
			log.Fatal(err)
		}
		go poll.run()
	} else if *mode != "goroutine" {
		log.Fatalf("unknown mode %q", *mode)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /hold", func(w http.ResponseWriter, r *http.Request) {
		if c := upgrade(w, r); c != nil {
			c.start()
		}
	})
	mux.HandleFunc("GET /pair", func(w http.ResponseWriter, r *http.Request) {
		c := upgrade(w, r)
		if c == nil {
			return
		}
		key := r.URL.Query().Get("id")
		pairsMu.Lock()
		other := waiting[key]
		if other == nil {
			waiting[key] = c
			pairsMu.Unlock()
			return
		}
		delete(waiting, key)
		c.peer, other.peer = other, c
		pairsMu.Unlock()
		other.start()
		c.start()
	})
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, _ *http.Request) {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"heapAllocBytes": m.HeapAlloc, "heapInuseBytes": m.HeapInuse, "stackInuseBytes": m.StackInuse,
			"runtimeSysBytes": m.Sys, "goroutines": runtime.NumGoroutine(), "openSockets": open.Load(),
		})
	})
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	fmt.Printf("{\"event\":\"listening\",\"address\":%q,\"mode\":%q}\n", *addr, *mode)
	log.Fatal(srv.ListenAndServe())
}

func upgrade(w http.ResponseWriter, r *http.Request) *conn {
	nc, rw, _, err := ws.UpgradeHTTP(r, w)
	if err != nil {
		return nil
	}
	if rw.Reader.Buffered() > 0 {
		_ = nc.Close()
		return nil
	}
	raw, err := nc.(syscall.Conn).SyscallConn()
	if err != nil {
		_ = nc.Close()
		return nil
	}
	c := &conn{id: nextID.Add(1), nc: nc, raw: raw}
	c.lastSeen.Store(time.Now().UnixNano())
	open.Add(1)
	return c
}

func (c *conn) start() {
	c.timer = time.AfterFunc(*heartbeat, c.tick)
	if poll != nil {
		if err := poll.add(c); err != nil {
			c.close()
		}
		return
	}
	go c.loop()
}

func (c *conn) loop() {
	for {
		if err := c.waitReadable(); err != nil {
			c.close()
			return
		}
		if err := c.serve(); err != nil {
			if debug {
				log.Printf("conn %d: serve: %v", c.id, err)
			}
			c.close()
			return
		}
	}
}

// Called by the poller when the socket is readable. Returns to the poller
// once the kernel receive queue is empty at a frame boundary.
func (c *conn) wake() {
	for {
		if err := c.serve(); err != nil {
			c.close()
			return
		}
		switch c.pending() {
		case pendingData:
			continue
		case pendingNone:
			if err := poll.rearm(c); err != nil {
				c.close()
			}
			return
		default:
			c.close()
			return
		}
	}
}

type pendingState int

const (
	pendingNone pendingState = iota
	pendingData
	pendingGone
)

func (c *conn) pending() pendingState {
	state := pendingGone
	_ = c.raw.Control(func(fd uintptr) {
		n, _, err := unix.Recvfrom(int(fd), c.peek[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		switch {
		case n > 0:
			state = pendingData
		case err == unix.EAGAIN:
			state = pendingNone
		}
	})
	return state
}

func (c *conn) waitReadable() error {
	_ = c.nc.SetReadDeadline(time.Now().Add(2 * *heartbeat))
	return c.raw.Read(func(fd uintptr) bool {
		n, _, err := unix.Recvfrom(int(fd), c.peek[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		return n > 0 || err != unix.EAGAIN
	})
}

// Reads complete frames with a pooled reader until it drains at a frame boundary.
func (c *conn) serve() error {
	br := readers.Get().(*bufio.Reader)
	br.Reset(c.nc)
	defer func() {
		br.Reset(nil)
		readers.Put(br)
	}()
	for {
		if err := c.frame(br); err != nil {
			return err
		}
		if br.Buffered() == 0 {
			return nil
		}
	}
}

func (c *conn) frame(br *bufio.Reader) error {
	_ = c.nc.SetReadDeadline(time.Now().Add(2 * *heartbeat))
	h, err := ws.ReadHeader(br)
	if err != nil {
		return err
	}
	if h.Rsv != 0 || !h.Masked || h.OpCode.IsReserved() {
		return errProtocol
	}
	c.lastSeen.Store(time.Now().UnixNano())
	if h.OpCode.IsControl() {
		if h.Length > ws.MaxControlFramePayloadSize || !h.Fin {
			return errProtocol
		}
		var p [ws.MaxControlFramePayloadSize]byte
		b := p[:h.Length]
		if _, err := io.ReadFull(br, b); err != nil {
			return err
		}
		ws.Cipher(b, h.Mask, 0)
		switch h.OpCode {
		case ws.OpPing:
			return c.control(ws.OpPong, b)
		case ws.OpClose:
			return errClosed
		}
		return nil
	}
	if c.fragmented != (h.OpCode == ws.OpContinuation) {
		return errProtocol
	}
	if !c.fragmented {
		c.msgBytes = 0
	}
	c.fragmented = !h.Fin
	c.msgBytes += h.Length
	if c.msgBytes > *maxMessage {
		return errTooBig
	}
	dst := c.peer
	if dst == nil {
		return errPolicy
	}
	return c.forward(br, dst, h)
}

func (c *conn) forward(br *bufio.Reader, dst *conn, h ws.Header) error {
	bp := writers.Get().(*[]byte)
	defer writers.Put(bp)
	buf := *bp
	dst.wmu.Lock()
	defer dst.wmu.Unlock()
	hs := putHeader(buf, h.Fin, h.OpCode, h.Length)
	off := 0
	for rem := h.Length; ; {
		n := 0
		if rem > 0 {
			var err error
			n, err = br.Read(buf[hs:min(int64(len(buf)), int64(hs)+rem)])
			if err != nil {
				return err
			}
			ws.Cipher(buf[hs:hs+n], h.Mask, off)
			off += n
			rem -= int64(n)
		}
		_ = dst.nc.SetWriteDeadline(time.Now().Add(deliveryTimeout))
		if _, err := dst.nc.Write(buf[:hs+n]); err != nil {
			dst.close()
			return err
		}
		hs = 0
		if rem == 0 {
			return nil
		}
	}
}

func putHeader(b []byte, fin bool, op ws.OpCode, n int64) int {
	b[0] = byte(op)
	if fin {
		b[0] |= 0x80
	}
	switch {
	case n < 126:
		b[1] = byte(n)
		return 2
	case n <= 0xffff:
		b[1] = 126
		binary.BigEndian.PutUint16(b[2:], uint16(n))
		return 4
	default:
		b[1] = 127
		binary.BigEndian.PutUint64(b[2:], uint64(n))
		return 10
	}
}

func (c *conn) control(op ws.OpCode, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.controlLocked(op, payload)
}

func (c *conn) controlLocked(op ws.OpCode, payload []byte) error {
	var b [2 + ws.MaxControlFramePayloadSize]byte
	n := putHeader(b[:], true, op, int64(len(payload)))
	n += copy(b[n:], payload)
	_ = c.nc.SetWriteDeadline(time.Now().Add(controlTimeout))
	_, err := c.nc.Write(b[:n])
	return err
}

func (c *conn) tick() {
	if c.closed.Load() {
		return
	}
	if time.Since(time.Unix(0, c.lastSeen.Load())) > 2**heartbeat {
		c.close()
		return
	}
	if c.wmu.TryLock() {
		err := c.controlLocked(ws.OpPing, nil)
		c.wmu.Unlock()
		if err != nil {
			c.close()
			return
		}
	}
	c.timer.Reset(*heartbeat)
}

func (c *conn) close() {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}
	if c.timer != nil {
		c.timer.Stop()
	}
	if poll != nil {
		poll.remove(c)
	}
	_ = c.nc.SetWriteDeadline(time.Now().Add(time.Second))
	_ = c.nc.Close()
	open.Add(-1)
	if c.peer != nil {
		c.peer.close()
	}
}
