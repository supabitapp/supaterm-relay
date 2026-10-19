package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/internal/endpoint"
)

var (
	base      = flag.String("url", "ws://127.0.0.1:8080", "relay WebSocket base URL")
	metrics   = flag.String("metrics", "http://127.0.0.1:9090/metrics", "relay metrics URL")
	pprofURL  = flag.String("pprof", "http://127.0.0.1:6060", "relay pprof base URL")
	pid       = flag.Int("pid", 0, "relay process ID for /proc sampling")
	steps     = flag.String("steps", "0,1000,5000,15000", "cumulative user counts to sample")
	hostsOnly = flag.Bool("hosts-only", false, "register hosts without pairing a client")
	ips       = flag.Int("ips", 32, "loopback source addresses")
	settle    = flag.Duration("settle", 20*time.Second, "idle time before each sample")
	workers   = flag.Int("workers", 128, "concurrent user setups")
	profiles  = flag.String("profiles", "", "directory for heap and goroutine profiles at the last step")
	mode      = flag.String("mode", "hold", "hold or bench")
)

type sample struct {
	Users      int    `json:"users"`
	Sockets    int    `json:"sockets"`
	RSSKiB     int64  `json:"rssKiB"`
	HeapAlloc  uint64 `json:"heapAllocBytes"`
	HeapInuse  uint64 `json:"heapInuseBytes"`
	StackInuse uint64 `json:"stackInuseBytes"`
	RuntimeSys uint64 `json:"runtimeSysBytes"`
	Goroutines int    `json:"goroutines"`
	Open       int    `json:"openSockets"`
}

var next atomic.Uint32

func main() {
	flag.Parse()
	endpoint.Dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		n := next.Add(1)
		local := net.IPv4(127, 0, byte(1+n%uint32(*ips)/250), byte(1+n%uint32(*ips)%250))
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: local}}
		return d.DialContext(ctx, network, addr)
	}
	if *mode == "bench" {
		if err := bench(); err != nil {
			fail(err)
		}
		return
	}
	var held []io.Closer
	users := 0
	targets := strings.Split(*steps, ",")
	for i, t := range targets {
		target, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			fail(err)
		}
		added, err := grow(target - users)
		held = append(held, added...)
		if err != nil {
			fail(fmt.Errorf("growing to %d users: %w", target, err))
		}
		users = target
		time.Sleep(*settle)
		s, err := measure()
		if err != nil {
			fail(err)
		}
		s.Users = users
		s.Sockets = users
		if !*hostsOnly {
			s.Sockets = 3 * users
		}
		line, _ := json.Marshal(s)
		fmt.Println(string(line))
		if i == len(targets)-1 && *profiles != "" {
			for _, p := range []string{"heap?gc=1", "goroutine"} {
				if err := save(p); err != nil {
					fail(err)
				}
			}
		}
	}
	for _, c := range held {
		_ = c.Close()
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "hold:", err)
	os.Exit(1)
}

func grow(n int) ([]io.Closer, error) {
	var mu sync.Mutex
	var out []io.Closer
	var first error
	jobs := make(chan struct{})
	var wg sync.WaitGroup
	for range *workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				conns, err := user()
				mu.Lock()
				out = append(out, conns...)
				if err != nil && first == nil {
					first = err
				}
				mu.Unlock()
			}
		}()
	}
	for range n {
		jobs <- struct{}{}
	}
	close(jobs)
	wg.Wait()
	return out, first
}

func user() ([]io.Closer, error) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	h, err := endpoint.Register(*base, priv)
	if err != nil {
		return nil, err
	}
	out := []io.Closer{h.Control}
	if *hostsOnly {
		return out, nil
	}
	c, _, err := endpoint.Connect(*base, h.ID)
	if err != nil {
		return out, err
	}
	out = append(out, c)
	ev, err := h.Next(30 * time.Second)
	if err != nil {
		return out, err
	}
	a, _, err := h.Accept(ev)
	if err != nil {
		return out, err
	}
	out = append(out, a)
	go drain(c)
	go drain(a)
	return out, nil
}

func drain(ws *websocket.Conn) {
	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			return
		}
	}
}

func measure() (sample, error) {
	var s sample
	for range 2 {
		if err := get(*pprofURL+"/debug/pprof/heap?gc=1", io.Discard); err != nil {
			return s, err
		}
	}
	var m struct {
		HeapAllocBytes  uint64 `json:"heapAllocBytes"`
		HeapInuseBytes  uint64 `json:"heapInuseBytes"`
		StackInuseBytes uint64 `json:"stackInuseBytes"`
		RuntimeSysBytes uint64 `json:"runtimeSysBytes"`
		Goroutines      int    `json:"goroutines"`
		OpenSockets     int    `json:"openSockets"`
	}
	var b strings.Builder
	if err := get(*metrics, &b); err != nil {
		return s, err
	}
	if err := json.Unmarshal([]byte(b.String()), &m); err != nil {
		return s, err
	}
	s.HeapAlloc, s.HeapInuse, s.StackInuse, s.RuntimeSys = m.HeapAllocBytes, m.HeapInuseBytes, m.StackInuseBytes, m.RuntimeSysBytes
	s.Goroutines, s.Open = m.Goroutines, m.OpenSockets
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", *pid))
	if err != nil {
		return s, err
	}
	for _, line := range strings.Split(string(status), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "VmRSS:" {
			s.RSSKiB, _ = strconv.ParseInt(f[1], 10, 64)
		}
	}
	return s, nil
}

func get(url string, w io.Writer) error {
	client := http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(w, resp.Body)
	return err
}

func save(profile string) error {
	name := strings.SplitN(profile, "?", 2)[0] + ".pprof"
	f, err := os.Create(filepath.Join(*profiles, name))
	if err != nil {
		return err
	}
	defer f.Close()
	return get(*pprofURL+"/debug/pprof/"+profile, f)
}
