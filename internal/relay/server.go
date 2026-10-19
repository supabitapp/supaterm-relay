package relay

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/internal/admission"
	"github.com/supabitapp/supaterm-relay/internal/dashboard"
)

const (
	closeGrace       = time.Second
	httpTimeout      = 5 * time.Second
	writeTimeout     = 5 * time.Second
	maxConnections   = 50_000
	topHostsReported = 20
	readBufferSize   = 1024
	writeBufferSize  = 16 * 1024
)

type Server struct {
	cfg           Config
	http          *http.Server
	private       *http.Server
	upgrader      websocket.Upgrader
	limiter       *admission.Limiter
	publicLimiter *admission.Limiter
	gate          *admission.Gate
	draining      atomic.Bool

	forwardedMessages atomic.Int64
	forwardedBytes    atomic.Int64
	superseded        atomic.Int64

	rejectionsMu sync.Mutex
	rejections   map[string]int64

	mu          sync.Mutex
	hosts       map[string]*host
	pairs       map[string]*pair
	pending     int
	active      int
	clientSlots int
	conns       map[*websocket.Conn]struct{}
}

func New(cfg Config) *Server {
	s := &Server{
		cfg: cfg,
		upgrader: websocket.Upgrader{
			HandshakeTimeout: writeTimeout,
			ReadBufferSize:   readBufferSize,
			WriteBufferSize:  writeBufferSize,
			WriteBufferPool:  &sync.Pool{},
			CheckOrigin:      func(*http.Request) bool { return true },
		},
		limiter:       admission.NewLimiter(cfg.AdmissionRate, cfg.admissionBurst()),
		publicLimiter: admission.NewLimiter(cfg.AdmissionRate, cfg.admissionBurst()),
		gate:          admission.NewGate(maxConnections, cfg.MaxConnectionsPerIP),
		rejections:    map[string]int64{},
		hosts:         map[string]*host{},
		pairs:         map[string]*pair{},
		conns:         map[*websocket.Conn]struct{}{},
	}
	admin := http.NewServeMux()
	admin.HandleFunc("GET /healthz", s.handleHealth)
	admin.HandleFunc("GET /metrics", s.handleMetrics)
	mux := http.NewServeMux()
	if cfg.PrivateAddr == "" {
		mux.Handle("GET /healthz", admin)
		mux.Handle("GET /metrics", admin)
	} else {
		mux.Handle("GET /metrics", s.limitPublic(http.HandlerFunc(s.handlePublicMetrics)))
	}
	mux.HandleFunc("GET /v1/control", s.admit(false, s.handleControl))
	mux.HandleFunc("GET /v1/connect", s.admit(false, s.handleConnect))
	mux.HandleFunc("GET /v1/accept", s.admit(true, s.handleAccept))
	mux.Handle("GET /dashboard/", http.StripPrefix("/dashboard", dashboard.New(s.dashboardStats, s.limitPublic)))
	s.http = newHTTPServer(mux)
	s.private = newHTTPServer(admin)
	return s
}

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           logPanicsWithoutPeer(handler),
		ReadHeaderTimeout: httpTimeout,
		ReadTimeout:       httpTimeout,
		WriteTimeout:      httpTimeout,
		IdleTimeout:       httpTimeout,
	}
}

func logPanicsWithoutPeer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				logPanic(v)
				panic(http.ErrAbortHandler)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func logPanic(v any) {
	if v != http.ErrAbortHandler {
		log.Printf("relay: panic: %v\n%s", v, panicFrames())
	}
}

func panicFrames() string {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(4, pcs)])
	var b strings.Builder
	for {
		frame, more := frames.Next()
		fmt.Fprintf(&b, "%s\n\t%s:%d\n", frame.Function, frame.File, frame.Line)
		if !more {
			return b.String()
		}
	}
}

func (s *Server) Serve(ln net.Listener) error {
	return s.http.Serve(ln)
}

func (s *Server) ServePrivate(ln net.Listener) error {
	return s.private.Serve(ln)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if s.draining.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "draining"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	s.writeMetrics(w, true)
}

func (s *Server) handlePublicMetrics(w http.ResponseWriter, _ *http.Request) {
	s.writeMetrics(w, false)
}

func (s *Server) limitPublic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.publicLimiter.Allow(admission.ClientIP(r, s.cfg.TrustedProxies), time.Now()) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) dashboardStats() dashboard.Stats {
	stats := dashboard.Stats{
		Draining:          s.draining.Load(),
		ForwardedMessages: s.forwardedMessages.Load(),
		ForwardedBytes:    s.forwardedBytes.Load(),
	}
	stats.RejectedConnections, stats.RejectedConnectionsByReason = s.rejectionCounts()
	s.mu.Lock()
	stats.ActiveHosts = len(s.hosts)
	stats.ActivePairs = s.active
	stats.PendingPairs = s.pending
	stats.OpenSockets = len(s.conns)
	s.mu.Unlock()
	return stats
}

func (s *Server) writeMetrics(w http.ResponseWriter, detailed bool) {
	s.mu.Lock()
	m := map[string]any{
		"activeHosts":  len(s.hosts),
		"activePairs":  s.active,
		"clientSlots":  s.clientSlots,
		"closingPairs": s.clientSlots - s.active - s.pending,
		"pendingPairs": s.pending,
		"openSockets":  len(s.conns),
	}
	if detailed {
		m["topHosts"] = s.topHosts()
	}
	s.mu.Unlock()
	m["openConnections"], m["openConnectionIPs"] = s.gate.Stats()
	m["maxConnectionsPerClient"] = s.cfg.MaxConnectionsPerIP
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	m["heapAllocBytes"] = memory.HeapAlloc
	m["heapInuseBytes"] = memory.HeapInuse
	m["heapSysBytes"] = memory.HeapSys
	m["heapReleasedBytes"] = memory.HeapReleased
	m["stackInuseBytes"] = memory.StackInuse
	m["runtimeSysBytes"] = memory.Sys
	m["totalAllocatedBytes"] = memory.TotalAlloc
	m["gcCycles"] = memory.NumGC
	m["supersededRegistrations"] = s.superseded.Load()
	m["forwardedMessages"] = s.forwardedMessages.Load()
	m["forwardedBytes"] = s.forwardedBytes.Load()
	m["rejectedConnections"], m["rejectedConnectionsByReason"] = s.rejectionCounts()
	m["rateLimiterEntries"] = s.limiter.Size()
	m["goroutines"] = runtime.NumGoroutine()
	m["draining"] = s.draining.Load()
	m["dataBufferBytesPerSocket"] = readBufferSize + writeBufferSize
	writeJSON(w, http.StatusOK, m)
}

// next returns the function that serves its upgraded socket, or nil once the
// request is finished.
func (s *Server) admit(duringDrain bool, next func(http.ResponseWriter, *http.Request) func()) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := admission.ClientIP(r, s.cfg.TrustedProxies)
		switch s.gate.Acquire(ip) {
		case admission.GlobalFull:
			s.reject(w, http.StatusServiceUnavailable, "connection capacity reached")
			return
		case admission.PerIPFull:
			s.reject(w, http.StatusTooManyRequests, "client connection capacity reached")
			return
		}
		var serve func()
		defer func() {
			if serve == nil {
				s.gate.Release(ip)
			}
		}()
		switch {
		case !duringDrain && s.draining.Load():
			s.reject(w, http.StatusServiceUnavailable, "draining")
		case !s.limiter.Allow(ip, time.Now()):
			s.reject(w, http.StatusTooManyRequests, "rate limited")
		default:
			serve = next(w, r)
		}
		if serve != nil {
			go s.serveSocket(ip, serve)
		}
	}
}

// Sockets outlive their HTTP handler so net/http can free the request's
// buffers and handler stack while the socket stays open.
func (s *Server) serveSocket(ip netip.Addr, serve func()) {
	defer s.gate.Release(ip)
	defer func() {
		if v := recover(); v != nil {
			logPanic(v)
		}
	}()
	serve()
}

type hostTraffic struct {
	Endpoint string `json:"endpoint"`
	BytesIn  int64  `json:"bytesIn"`
	BytesOut int64  `json:"bytesOut"`
	Pairs    int    `json:"pairs"`
}

// topHosts is called with s.mu held. Keep only the small, sorted result rather
// than allocating and sorting every host while blocking connection lifecycle work.
func (s *Server) topHosts() []hostTraffic {
	hosts := make([]hostTraffic, 0, min(len(s.hosts), topHostsReported))
	for id, h := range s.hosts {
		in, out := h.bytesIn.Load(), h.bytesOut.Load()
		total := in + out
		if total == 0 {
			continue
		}
		i := len(hosts)
		if i == topHostsReported {
			i--
			if total <= hosts[i].BytesIn+hosts[i].BytesOut {
				continue
			}
		} else {
			hosts = append(hosts, hostTraffic{})
		}
		for i > 0 && total > hosts[i-1].BytesIn+hosts[i-1].BytesOut {
			hosts[i] = hosts[i-1]
			i--
		}
		hosts[i] = hostTraffic{Endpoint: id[:16], BytesIn: in, BytesOut: out, Pairs: len(h.pairs)}
	}
	return hosts
}

func (s *Server) reject(w http.ResponseWriter, status int, msg string) {
	s.countRejection(msg)
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) countRejection(reason string) {
	s.rejectionsMu.Lock()
	s.rejections[reason]++
	s.rejectionsMu.Unlock()
}

func (s *Server) rejectionCounts() (total int64, byReason map[string]int64) {
	s.rejectionsMu.Lock()
	defer s.rejectionsMu.Unlock()
	for _, n := range s.rejections {
		total += n
	}
	return total, maps.Clone(s.rejections)
}

func (s *Server) upgrade(w http.ResponseWriter, r *http.Request, limit int64) (*websocket.Conn, bool) {
	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, false
	}
	ws.SetReadLimit(limit)
	s.mu.Lock()
	s.conns[ws] = struct{}{}
	s.mu.Unlock()
	return ws, true
}

func (s *Server) closeNow(ws *websocket.Conn, c closeMsg) {
	deadline := time.Now().Add(closeGrace)
	ws.SetPongHandler(nil)
	_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(c.code, c.reason), deadline)
	_ = ws.SetReadDeadline(deadline)
	for {
		if _, _, err := ws.NextReader(); err != nil {
			break
		}
	}
	s.forget(ws)
}

func (s *Server) forget(ws *websocket.Conn) {
	_ = ws.Close()
	s.mu.Lock()
	delete(s.conns, ws)
	s.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(v)
}

func textFrame(v any) frame {
	b, _ := json.Marshal(v)
	return frame{typ: websocket.TextMessage, data: b}
}

func randomB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
