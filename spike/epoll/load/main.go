package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var (
	base     = flag.String("url", "ws://127.0.0.1:8080", "server WebSocket base URL")
	stats    = flag.String("stats", "http://127.0.0.1:8080/stats", "server stats URL")
	pid      = flag.Int("pid", 0, "server process ID")
	mode     = flag.String("mode", "hold", "hold or bench")
	steps    = flag.String("steps", "0,1000,5000,15000", "cumulative users to sample in hold mode")
	ips      = flag.Int("ips", 32, "loopback source addresses")
	settle   = flag.Duration("settle", 20*time.Second, "idle time before each hold sample")
	workers  = flag.Int("workers", 128, "concurrent setups")
	payloads = flag.String("payloads", "64,1024,65536", "bench payload sizes")
	clients  = flag.String("clients", "1,32", "bench pair counts")
	inflight = flag.Int("inflight", 4, "bench messages in flight per client")
	warmup   = flag.Duration("warmup", 2*time.Second, "bench warmup")
	duration = flag.Duration("duration", 5*time.Second, "bench window")
)

var (
	next   atomic.Uint32
	keys   atomic.Uint64
	dialer = &websocket.Dialer{HandshakeTimeout: 10 * time.Second, ReadBufferSize: 4096, WriteBufferSize: 4096,
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			if *ips > 0 {
				d.LocalAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 1, byte(1+next.Add(1)%uint32(*ips)))}
			}
			return d.DialContext(ctx, network, addr)
		}}
)

func main() {
	flag.Parse()
	var err error
	switch *mode {
	case "hold":
		err = hold()
	case "bench":
		err = bench()
	case "stall":
		err = stall()
	case "flood":
		err = flood()
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
}

func pair() (*websocket.Conn, *websocket.Conn, error) {
	key := strconv.FormatUint(keys.Add(1), 10)
	a, _, err := dialer.Dial(*base+"/pair?id="+key, nil)
	if err != nil {
		return nil, nil, err
	}
	b, _, err := dialer.Dial(*base+"/pair?id="+key, nil)
	if err != nil {
		a.Close()
		return nil, nil, err
	}
	return a, b, nil
}

func hold() error {
	var mu sync.Mutex
	var held []io.Closer
	users := 0
	for _, t := range strings.Split(*steps, ",") {
		target, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return err
		}
		jobs := make(chan struct{})
		var wg sync.WaitGroup
		var first atomic.Value
		for range *workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range jobs {
					h, _, err := dialer.Dial(*base+"/hold", nil)
					if err != nil {
						first.CompareAndSwap(nil, err)
						continue
					}
					a, b, err := pair()
					if err != nil {
						first.CompareAndSwap(nil, err)
						continue
					}
					for _, c := range []*websocket.Conn{h, a, b} {
						go drain(c)
					}
					mu.Lock()
					held = append(held, h, a, b)
					mu.Unlock()
				}
			}()
		}
		for range target - users {
			jobs <- struct{}{}
		}
		close(jobs)
		wg.Wait()
		if err, ok := first.Load().(error); ok {
			return err
		}
		users = target
		time.Sleep(*settle)
		s, err := sample()
		if err != nil {
			return err
		}
		s["users"], s["sockets"] = users, 3*users
		line, _ := json.Marshal(s)
		fmt.Println(string(line))
	}
	for _, c := range held {
		_ = c.Close()
	}
	return nil
}

// Opens idle sockets, then makes each send one byte of a frame header and stop.
func stall() error {
	n := ints(*steps)[0]
	var held []*websocket.Conn
	for range n {
		c, _, err := dialer.Dial(*base+"/hold", nil)
		if err != nil {
			return err
		}
		held = append(held, c)
		go drain(c)
	}
	time.Sleep(*settle)
	before, err := sample()
	if err != nil {
		return err
	}
	for _, c := range held {
		if _, err := c.NetConn().Write([]byte{0x82}); err != nil {
			return err
		}
	}
	time.Sleep(*settle)
	after, err := sample()
	if err != nil {
		return err
	}
	line, _ := json.Marshal(map[string]any{"sockets": n, "idle": before, "stalledMidHeader": after})
	fmt.Println(string(line))
	return nil
}

// Pairs whose receivers never read while their senders write 1 MiB messages.
func flood() error {
	n := ints(*steps)[0]
	msg := make([]byte, 1<<20)
	var sent atomic.Int64
	var receivers []*websocket.Conn
	defer func() { runtime.KeepAlive(receivers) }()
	for range n {
		a, b, err := pair()
		receivers = append(receivers, b)
		if err != nil {
			return err
		}
		go func() {
			for {
				_ = a.SetWriteDeadline(time.Now().Add(*settle * 2))
				if a.WriteMessage(websocket.BinaryMessage, msg) != nil {
					return
				}
				sent.Add(1)
			}
		}()
	}
	time.Sleep(*settle)
	s, err := sample()
	if err != nil {
		return err
	}
	s["pairs"], s["messagesAcceptedBeforeStall"] = n, sent.Load()
	line, _ := json.Marshal(s)
	fmt.Println(string(line))
	return nil
}

func drain(ws *websocket.Conn) {
	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			return
		}
	}
}

func sample() (map[string]any, error) {
	resp, err := http.Get(*stats)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	s := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}
	rss, _ := procRSS(*pid)
	s["rssKiB"] = rss
	return s, nil
}

func procRSS(pid int) (int64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "VmRSS:" {
			return strconv.ParseInt(f[1], 10, 64)
		}
	}
	return 0, nil
}

func procCPU(pid int) float64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+2:]))
	u, _ := strconv.ParseFloat(f[11], 64)
	s, _ := strconv.ParseFloat(f[12], 64)
	return (u + s) / 100
}

func ints(v string) []int {
	var out []int
	for _, f := range strings.Split(v, ",") {
		n, _ := strconv.Atoi(strings.TrimSpace(f))
		out = append(out, n)
	}
	return out
}

func bench() error {
	for _, size := range ints(*payloads) {
		for _, n := range ints(*clients) {
			r, err := runBench(size, n)
			if err != nil {
				return err
			}
			line, _ := json.Marshal(r)
			fmt.Println(string(line))
		}
	}
	return nil
}

type client struct {
	ws       *websocket.Conn
	rtts     []int64
	recv     int64
	bytes    int64
	sent     atomic.Int64
	got      atomic.Int64
	failures int64
	corrupt  int64
}

func runBench(size, n int) (map[string]any, error) {
	block := make([]byte, max(size, 16))
	_, _ = rand.Read(block)
	var cs []*client
	var echoes []*websocket.Conn
	for range n {
		a, b, err := pair()
		if err != nil {
			return nil, err
		}
		a.SetReadLimit(1 << 20)
		b.SetReadLimit(1 << 20)
		cs = append(cs, &client{ws: a})
		echoes = append(echoes, b)
		go func() {
			for {
				typ, data, err := b.ReadMessage()
				if err != nil || b.WriteMessage(typ, data) != nil {
					return
				}
			}
		}()
	}
	start := time.Now()
	mStart, mEnd := warmup.Nanoseconds(), (*warmup + *duration).Nanoseconds()
	stopAt := start.Add(*warmup + *duration)
	var cpu0, cpu1 float64
	var t0, t1 time.Time
	go func() {
		time.Sleep(*warmup)
		cpu0, t0 = procCPU(*pid), time.Now()
		time.Sleep(*duration)
		cpu1, t1 = procCPU(*pid), time.Now()
	}()
	var wg sync.WaitGroup
	for _, c := range cs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.run(block, start, mStart, mEnd, stopAt)
		}()
	}
	wg.Wait()
	for _, e := range echoes {
		e.Close()
	}
	time.Sleep(100 * time.Millisecond)
	var rtts []int64
	var msgs, bytesIn, failures, corrupt int64
	for _, c := range cs {
		rtts = append(rtts, c.rtts...)
		msgs += c.recv
		bytesIn += c.bytes
		failures += c.failures + c.sent.Load() - c.got.Load()
		corrupt += c.corrupt
	}
	slices.Sort(rtts)
	q := func(p float64) float64 {
		if len(rtts) == 0 {
			return 0
		}
		return round(float64(rtts[max(0, int(math.Ceil(p*float64(len(rtts))))-1)]) / 1e3)
	}
	return map[string]any{
		"payloadBytes": size, "clients": n,
		"messagesPerSec":   round(float64(msgs) / duration.Seconds()),
		"payloadMiBPerSec": round(float64(bytesIn) / duration.Seconds() / (1 << 20)),
		"rttP50Micros":     q(0.5), "rttP99Micros": q(0.99),
		"cpuPercentOfOneCore": round(100 * (cpu1 - cpu0) / t1.Sub(t0).Seconds()),
		"failures":            failures, "corrupt": corrupt,
	}, nil
}

func (c *client) run(block []byte, base time.Time, mStart, mEnd int64, stopAt time.Time) {
	sem := make(chan struct{}, *inflight)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var expect uint64
		for {
			_, data, err := c.ws.ReadMessage()
			if err != nil {
				return
			}
			now := time.Since(base).Nanoseconds()
			if len(data) != len(block) || binary.BigEndian.Uint64(data) != expect || !bytes.Equal(data[16:], block[16:]) {
				c.corrupt++
			}
			expect++
			if sentAt := int64(binary.BigEndian.Uint64(data[8:])); sentAt >= mStart && sentAt < mEnd {
				c.rtts = append(c.rtts, now-sentAt)
			}
			if now >= mStart && now < mEnd {
				c.recv++
				c.bytes += int64(len(data))
			}
			c.got.Add(1)
			<-sem
		}
	}()
	for seq := uint64(0); time.Now().Before(stopAt); seq++ {
		select {
		case sem <- struct{}{}:
		case <-done:
			c.failures++
			return
		case <-time.After(5 * time.Second):
			c.failures++
			c.ws.Close()
			<-done
			return
		}
		msg := slices.Clone(block)
		binary.BigEndian.PutUint64(msg, seq)
		binary.BigEndian.PutUint64(msg[8:], uint64(time.Since(base).Nanoseconds()))
		_ = c.ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if c.ws.WriteMessage(websocket.BinaryMessage, msg) != nil {
			c.failures++
			break
		}
		c.sent.Add(1)
	}
	end := time.Now().Add(5 * time.Second)
	for c.got.Load() < c.sent.Load() && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	c.ws.Close()
	<-done
}

func round(v float64) float64 {
	return math.Round(v*10) / 10
}
