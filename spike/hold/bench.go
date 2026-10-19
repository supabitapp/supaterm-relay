package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/internal/endpoint"
)

var (
	payloads = flag.String("payloads", "64,1024,65536", "bench payload sizes")
	clients  = flag.String("clients", "1,32", "bench client counts")
	inflight = flag.Int("inflight", 4, "bench messages in flight per client")
	warmup   = flag.Duration("warmup", 2*time.Second, "bench warmup")
	duration = flag.Duration("duration", 5*time.Second, "bench window")
)

var benchHosts []*endpoint.Host

func relayPair() (*websocket.Conn, *websocket.Conn, error) {
	if len(benchHosts) == 0 {
		for range 4 {
			_, priv, _ := ed25519.GenerateKey(rand.Reader)
			h, err := endpoint.Register(*base, priv)
			if err != nil {
				return nil, nil, err
			}
			benchHosts = append(benchHosts, h)
		}
	}
	h := benchHosts[int(next.Add(1))%len(benchHosts)]
	c, _, err := endpoint.Connect(*base, h.ID)
	if err != nil {
		return nil, nil, err
	}
	ev, err := h.Next(10 * time.Second)
	for err == nil && ev.Type != "incoming" {
		ev, err = h.Next(10 * time.Second)
	}
	if err != nil {
		return nil, nil, err
	}
	a, _, err := h.Accept(ev)
	if err != nil {
		return nil, nil, err
	}
	return c, a, nil
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
		a, b, err := relayPair()
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
