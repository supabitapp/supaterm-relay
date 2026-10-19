package main

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/internal/endpoint"
)

var (
	relayURL   = flag.String("url", "", "WebSocket base URL of the relay")
	spawnRelay = flag.Bool("spawn", false, "start a relay on loopback")
	relayBin   = flag.String("relay-bin", "bin/relay", "relay binary for -spawn")
	payloads   = flag.String("payloads", "64,1024,65536", "payload sizes in bytes")
	clients    = flag.String("clients", "1,32", "concurrent client counts")
	inflight   = flag.Int("inflight", 4, "messages in flight per client")
	warmup     = flag.Duration("warmup", 2*time.Second, "warmup per case")
	duration   = flag.Duration("duration", 5*time.Second, "measurement window per case")
	hostCount  = flag.Int("hosts", 4, "echo hosts")
)

type dist struct {
	P50 float64 `json:"p50"`
	P99 float64 `json:"p99"`
	Max float64 `json:"max"`
}

type usage struct {
	CPUPercent float64 `json:"cpuPercentOfOneCore"`
	RSSPeakMiB float64 `json:"rssPeakMiB"`
}

type result struct {
	Payload   int              `json:"payloadBytes"`
	Clients   int              `json:"clients"`
	Messages  int64            `json:"messagesInWindow"`
	MsgPerSec float64          `json:"messagesPerSec"`
	MiBPerSec float64          `json:"payloadMiBPerSec"`
	RTT       dist             `json:"rttMicros"`
	Failures  int64            `json:"failures"`
	Corrupt   int64            `json:"corrupt"`
	Processes map[string]usage `json:"processes,omitempty"`
}

type target struct {
	base  string
	hosts []*endpoint.Host
	pids  map[string]int
}

func main() {
	flag.Parse()
	if err := benchmark(); err != nil {
		fmt.Fprintln(os.Stderr, "relay-bench:", err)
		os.Exit(1)
	}
}

func benchmark() error {
	if *hostCount <= 0 || *inflight <= 0 || *warmup < 0 || *duration <= 0 {
		return errors.New("hosts, inflight and duration must be positive; warmup must not be negative")
	}
	sizes, err := ints(*payloads)
	if err != nil {
		return err
	}
	counts, err := ints(*clients)
	if err != nil {
		return err
	}
	pids := map[string]int{}
	if *spawnRelay {
		clientLimit := cmp.Or(os.Getenv("RELAY_MAX_CLIENTS_PER_HOST_PER_IP"), os.Getenv("RELAY_MAX_CLIENTS_PER_HOST"), "64")
		process, address, err := spawn(*relayBin, "RELAY_ADDR=127.0.0.1:0", "RELAY_PRIVATE_ADDR=", "RELAY_ADMISSION_RATE=1000000", "RELAY_MAX_CONNS_PER_IP=100000", "RELAY_MAX_CLIENTS_PER_HOST_PER_IP="+clientLimit)
		if process != nil {
			defer func() {
				_ = process.Process.Signal(syscall.SIGTERM)
				_ = process.Wait()
			}()
		}
		if err != nil {
			return err
		}

		pids["relay"] = process.Process.Pid
		*relayURL = "ws://" + address
	}
	if *relayURL == "" {
		return errors.New("-url or -spawn is required")
	}
	hosts, err := serveEcho(*relayURL, *hostCount)
	if err != nil {
		return fmt.Errorf("echo hosts: %w", err)
	}
	defer func() {
		for _, host := range hosts {
			host.Close()
		}
	}()
	tg := &target{base: *relayURL, hosts: hosts, pids: pids}
	var results []result
	for _, size := range sizes {
		for _, count := range counts {
			r, err := run(tg, size, count)
			if err != nil {
				return fmt.Errorf("%dB x%d: %w", size, count, err)
			}
			fmt.Fprintf(os.Stderr, "%6dB x%-3d p50=%.0fus p99=%.0fus %8.0f msg/s %7.1f MiB/s %v fail=%d corrupt=%d\n", r.Payload, r.Clients, r.RTT.P50, r.RTT.P99, r.MsgPerSec, r.MiBPerSec, r.Processes, r.Failures, r.Corrupt)
			results = append(results, r)
			if r.Failures > 0 || r.Corrupt > 0 {
				return errors.New("echo validation failed")
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"url": *relayURL, "spawned": *spawnRelay,
		"warmupSec": warmup.Seconds(), "durationSec": duration.Seconds(), "inflightPerClient": *inflight, "hosts": *hostCount,
		"driver":  map[string]any{"goos": runtime.GOOS, "goarch": runtime.GOARCH, "cpus": runtime.NumCPU(), "go": runtime.Version()},
		"results": results,
	})
}

func ints(v string) ([]int, error) {
	var out []int
	for f := range strings.SplitSeq(v, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid list %q", v)
		}
		out = append(out, n)
	}
	return out, nil
}

func spawn(bin string, env ...string) (*exec.Cmd, string, error) {
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, "", err
	}
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		var ev struct{ Event, Address, Listener string }
		if json.Unmarshal(sc.Bytes(), &ev) == nil && ev.Event == "listening" && ev.Listener != "private" {
			go func() {
				for sc.Scan() {
				}
			}()
			return cmd, ev.Address, nil
		}
	}
	return cmd, "", fmt.Errorf("%s did not report listening", bin)
}

func serveEcho(base string, n int) ([]*endpoint.Host, error) {
	var hosts []*endpoint.Host
	for range n {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		h, err := endpoint.Register(base, priv)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
		go func() {
			for ev := range h.Events {
				if ev.Type != "incoming" {
					continue
				}
				go func() {
					ws, _, err := h.Accept(ev)
					if err != nil {
						return
					}
					defer ws.Close()
					ws.SetReadLimit(1 << 20)
					for {
						typ, data, err := ws.ReadMessage()
						if err != nil || ws.WriteMessage(typ, data) != nil {
							return
						}
					}
				}()
			}
		}()
	}
	return hosts, nil
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

func run(tg *target, size, n int) (result, error) {
	res := result{Payload: size, Clients: n}
	block := make([]byte, max(size, 16))
	_, _ = rand.Read(block)
	cs := make([]*client, n)
	var wg sync.WaitGroup
	var dialErr atomic.Value
	for i := range cs {
		wg.Go(func() {
			ws, resp, err := endpoint.Connect(tg.base, tg.hosts[i%len(tg.hosts)].ID)
			if err != nil {
				if resp != nil {
					err = fmt.Errorf("%w (HTTP %d)", err, resp.StatusCode)
				}
				dialErr.Store(err)
				return
			}
			ws.SetReadLimit(1 << 20)
			cs[i] = &client{ws: ws}
		})
	}
	wg.Wait()
	defer func() {
		for _, c := range cs {
			if c != nil {
				c.ws.Close()
			}
		}
	}()
	if err, _ := dialErr.Load().(error); err != nil {
		return res, err
	}
	base := time.Now()
	mStart := (*warmup).Nanoseconds()
	mEnd := (*warmup + *duration).Nanoseconds()
	stopAt := base.Add(*warmup + *duration)
	samplers := make(chan map[string]*sampler, 1)
	go func() {
		time.Sleep(*warmup)
		m := map[string]*sampler{}
		for name, pid := range tg.pids {
			m[name] = startSampler(pid)
		}
		samplers <- m
	}()
	for _, c := range cs {
		wg.Go(func() {
			c.run(block, base, mStart, mEnd, stopAt)
		})
	}
	wg.Wait()
	for name, s := range <-samplers {
		if res.Processes == nil {
			res.Processes = map[string]usage{}
		}
		res.Processes[name] = s.stop()
	}
	var rtts []int64
	var bytesIn int64
	for _, c := range cs {
		rtts = append(rtts, c.rtts...)
		res.Messages += c.recv
		res.Failures += c.failures + c.sent.Load() - c.got.Load()
		res.Corrupt += c.corrupt
		bytesIn += c.bytes
	}
	res.MsgPerSec = round(float64(res.Messages) / duration.Seconds())
	res.MiBPerSec = round(float64(bytesIn) / duration.Seconds() / (1 << 20))
	res.RTT = summarize(rtts)
	return res, nil
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

func summarize(ns []int64) dist {
	if len(ns) == 0 {
		return dist{}
	}
	slices.Sort(ns)
	q := func(p float64) float64 {
		return round(float64(ns[max(0, int(math.Ceil(p*float64(len(ns))))-1)]) / 1e3)
	}
	return dist{P50: q(0.5), P99: q(0.99), Max: q(1)}
}

func round(v float64) float64 {
	return math.Round(v*10) / 10
}

type sampler struct {
	pid   int
	start time.Time
	cpu0  float64
	peak  int64
	stopc chan struct{}
	done  chan struct{}
}

func psStats(pid int) (int64, float64, error) {
	out, err := exec.Command("ps", "-o", "rss=,time=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return 0, 0, err
	}
	f := strings.Fields(string(out))
	if len(f) != 2 {
		return 0, 0, fmt.Errorf("unexpected ps output %q", out)
	}
	rss, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	var cpu float64
	for part := range strings.SplitSeq(strings.ReplaceAll(f[1], "-", ":"), ":") {
		v, err := strconv.ParseFloat(part, 64)
		if err != nil {
			return 0, 0, err
		}
		cpu = cpu*60 + v
	}
	return rss, cpu, nil
}

func startSampler(pid int) *sampler {
	s := &sampler{pid: pid, start: time.Now(), stopc: make(chan struct{}), done: make(chan struct{})}
	_, s.cpu0, _ = psStats(pid)
	go func() {
		defer close(s.done)
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			if rss, _, err := psStats(pid); err == nil {
				s.peak = max(s.peak, rss)
			}
			select {
			case <-t.C:
			case <-s.stopc:
				return
			}
		}
	}()
	return s
}

func (s *sampler) stop() usage {
	close(s.stopc)
	<-s.done
	rss, cpu, _ := psStats(s.pid)
	return usage{CPUPercent: round(100 * (cpu - s.cpu0) / time.Since(s.start).Seconds()), RSSPeakMiB: round(float64(max(s.peak, rss)) / 1024)}
}
