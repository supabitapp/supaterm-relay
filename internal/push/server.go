package push

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/supabitapp/supaterm-relay/internal/admission"
	"github.com/supabitapp/supaterm-relay/internal/dashboard"
)

const (
	upstreamTimeout    = 10 * time.Second
	maxPlatformPayload = 4096
	maxUpstreamReply   = 4096
	maxPushBody        = 4096
	maxJSONBody        = 8 << 10
	maxTTL             = 28 * 24 * time.Hour
	subscriptionTTL    = 10 * time.Minute
	maxTokenLength     = 512
	maxRequestIDLength = 64
	retryAfterSeconds  = "60"
)

var alertText = map[string]string{
	"activity":    "New activity",
	"completed":   "An agent finished",
	"needs-input": "An agent needs your input",
	"failed":      "An agent ran into a problem",
}

type apiError struct {
	status int
	code   string
}

func (e apiError) Error() string {
	return e.code
}

var (
	errInvalidRequest        = apiError{http.StatusBadRequest, "invalid_request"}
	errPlatformNotConfigured = apiError{http.StatusBadRequest, "platform_not_configured"}
	errUnauthorized          = apiError{http.StatusUnauthorized, "unauthorized"}
	errEndpointExpired       = apiError{http.StatusForbidden, "endpoint_expired"}
	errTopicNotAllowed       = apiError{http.StatusForbidden, "topic_not_allowed"}
	errEndpointInvalid       = apiError{http.StatusNotFound, "endpoint_invalid"}
	errRenewalTooEarly       = apiError{http.StatusConflict, "renewal_too_early"}
	errEndpointRevoked       = apiError{http.StatusGone, "endpoint_revoked"}
	errTokenUnregistered     = apiError{http.StatusGone, "token_unregistered"}
	errPayloadTooLarge       = apiError{http.StatusRequestEntityTooLarge, "payload_too_large"}
	errUnsupportedEncoding   = apiError{http.StatusUnsupportedMediaType, "unsupported_encoding"}
	errRateLimited           = apiError{http.StatusTooManyRequests, "rate_limited"}
	errUpstreamUnavailable   = apiError{http.StatusBadGateway, "upstream_unavailable"}
	errGatewayMisconfigured  = apiError{http.StatusServiceUnavailable, "gateway_misconfigured"}
	errRevocationUnavailable = apiError{http.StatusServiceUnavailable, "revocation_unavailable"}
)

type outcome int

const (
	delivered outcome = iota
	tokenGone
	tooLarge
	unavailable
	misconfigured
)

type result struct {
	outcome outcome
	status  int
	reason  string
}

type notification struct {
	title  string
	body   string
	sound  bool
	urgent bool
	ttl    time.Duration
	data   map[string]string
}

type platform interface {
	deliver(ctx context.Context, g grant, n notification, now time.Time) result
}

type Server struct {
	cfg       Config
	log       *slog.Logger
	now       func() time.Time
	sealer    sealer
	revoked   *revocations
	platforms map[string]platform
	http      *http.Server
	draining  atomic.Bool

	phones  *admission.Limiter
	devices *admission.Keyed[[sha256.Size]byte]
	hosts   *admission.Limiter
	grants  *admission.Keyed[string]
	viewers *admission.Limiter

	issued         atomic.Int64
	renewed        atomic.Int64
	delivered      atomic.Int64
	deliveredBytes atomic.Int64

	rejectionsMu sync.Mutex
	rejections   map[string]int64
}

func New(cfg Config, log *slog.Logger) (*Server, error) {
	return newServer(cfg, log, time.Now)
}

func newServer(cfg Config, log *slog.Logger, now func() time.Time) (*Server, error) {
	s := &Server{
		cfg:        cfg,
		log:        log,
		now:        now,
		sealer:     newSealer(cfg.SealKeys, cfg.PublicURL),
		platforms:  map[string]platform{},
		phones:     admission.NewLimiter(60.0/3600, 20),
		devices:    admission.NewKeyed[[sha256.Size]byte](20.0/3600, 10),
		hosts:      admission.NewLimiter(20, 200),
		grants:     admission.NewKeyed[string](0.5, 10),
		viewers:    admission.NewLimiter(5, 20),
		rejections: map[string]int64{},
	}
	revoked, err := openRevocations(cfg.RevocationFile, func() time.Time { return s.now() })
	if err != nil {
		return nil, err
	}
	s.revoked = revoked
	if len(cfg.APNs.Keys) > 0 {
		s.platforms["apns"] = newAPNsClient(cfg.APNs)
	}
	if cfg.FCM != nil {
		s.platforms["fcm"] = newFCMClient(*cfg.FCM)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.Handle("POST /v1/subscriptions", s.handle(s.subscribe))
	mux.Handle("POST /v1/subscriptions/renew", s.handle(s.renew))
	mux.Handle("POST /v1/subscriptions/revoke", s.handle(s.revoke))
	mux.Handle("POST "+pushPath+"{endpoint}", s.handle(s.push))
	mux.Handle("GET /dashboard/", http.StripPrefix("/dashboard", dashboard.New("push", s.dashboardStats, s.limitViewers)))
	s.http = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      upstreamTimeout + 5*time.Second,
		IdleTimeout:       time.Minute,
	}
	return s, nil
}

func (s *Server) Serve(ln net.Listener) error {
	return s.http.Serve(ln)
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.draining.Store(true)
	return errors.Join(s.http.Shutdown(ctx), s.revoked.close())
}

func (s *Server) handle(fn func(http.ResponseWriter, *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			var apiErr apiError
			if !errors.As(err, &apiErr) {
				s.log.Error("request failed", "error", err)
				apiErr = errUpstreamUnavailable
			}
			s.reject(w, apiErr)
		}
	})
}

func (s *Server) reject(w http.ResponseWriter, e apiError) {
	s.rejectionsMu.Lock()
	s.rejections[strings.ReplaceAll(e.code, "_", " ")]++
	s.rejectionsMu.Unlock()
	if e.status == http.StatusTooManyRequests || e.status >= 500 {
		w.Header().Set("Retry-After", retryAfterSeconds)
	}
	writeJSON(w, e.status, map[string]string{"error": e.code})
}

func (s *Server) subscribe(w http.ResponseWriter, r *http.Request) error {
	if !s.phones.Allow(s.clientIP(r), s.now()) {
		return errRateLimited
	}
	var req struct {
		Platform      string `json:"platform"`
		Token         string `json:"token"`
		Topic         string `json:"topic"`
		Environment   string `json:"environment"`
		HostKey       string `json:"hostKey"`
		ManagementKey string `json:"managementKey"`
		Request       string `json:"request"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		return err
	}
	hostKey, hostOK := parseP256(req.HostKey)
	managementKey, managementOK := parseP256(req.ManagementKey)
	if !hostOK || !managementOK || !validRequestID(req.Request) {
		return errInvalidRequest
	}
	g, err := s.target(grant{
		ID:            newGrantID(),
		Platform:      req.Platform,
		Token:         req.Token,
		Topic:         req.Topic,
		Environment:   req.Environment,
		HostKey:       hostKey,
		ManagementKey: managementKey,
	})
	if err != nil {
		return err
	}
	g, sub := s.sealer.issue(g, s.now())
	if err := s.sendSubscription(r.Context(), g, sub, req.Request); err != nil {
		return err
	}
	s.issued.Add(1)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "sent"})
	return nil
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request) error {
	if !s.phones.Allow(s.clientIP(r), s.now()) {
		return errRateLimited
	}
	jws, err := readBody(w, r, maxJWSLength)
	if err != nil {
		return err
	}
	req, current, err := verifyPhoneRequest(s.sealer, jws, "renew", s.now())
	if err != nil {
		return err
	}
	g := current
	g.Token = cmp.Or(req.Token, current.Token)
	if g, err = s.target(g); err != nil {
		return err
	}
	retarget := g.Token != current.Token
	if retarget && !validRequestID(req.Request) {
		return errInvalidRequest
	}
	var sub subscription
	err = s.revoked.unlessRevoked(g.ID, func(now time.Time) error {
		switch {
		case g.expired(now):
			return errEndpointExpired
		case !retarget && !g.renewable(now):
			return errRenewalTooEarly
		}
		g, sub = s.sealer.issue(g, now)
		return nil
	})
	if err != nil {
		return err
	}
	if retarget {
		if err := s.sendSubscription(r.Context(), g, sub, req.Request); err != nil {
			return err
		}
		s.renewed.Add(1)
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "sent"})
		return nil
	}
	s.renewed.Add(1)
	writeJSON(w, http.StatusOK, sub)
	return nil
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) error {
	if !s.phones.Allow(s.clientIP(r), s.now()) {
		return errRateLimited
	}
	jws, err := readBody(w, r, maxJWSLength)
	if err != nil {
		return err
	}
	_, g, err := verifyPhoneRequest(s.sealer, jws, "revoke", s.now())
	if err != nil {
		return err
	}
	if err := s.revoked.revoke(g.ID); err != nil {
		s.log.Error("store revocation", "error", err)
		return errRevocationUnavailable
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) push(w http.ResponseWriter, r *http.Request) error {
	now := s.now()
	if !s.hosts.Allow(s.clientIP(r), now) {
		return errRateLimited
	}
	g, ok := s.sealer.grant(r.PathValue("endpoint"))
	switch {
	case !ok:
		return errEndpointInvalid
	case !hostAuthorized(g, r.Header.Get("Authorization"), s.cfg.PublicURL, now):
		return errUnauthorized
	case s.revoked.revoked(g.ID):
		return errEndpointRevoked
	case g.expired(now):
		return errEndpointExpired
	case !s.grants.Allow(g.ID, now):
		return errRateLimited
	}
	if _, err := s.target(g); err != nil {
		return errGatewayMisconfigured
	}
	n, err := messageNotification(r.Header)
	if err != nil {
		return err
	}
	body, err := readBody(w, r, maxPushBody)
	if err != nil {
		return err
	}
	if body == "" {
		return errInvalidRequest
	}
	n.data["c"] = base64.RawURLEncoding.EncodeToString([]byte(body))
	if err := s.deliver(r.Context(), g, n); err != nil {
		return err
	}
	s.delivered.Add(1)
	s.deliveredBytes.Add(int64(len(body)))
	w.WriteHeader(http.StatusCreated)
	return nil
}

func messageNotification(h http.Header) (notification, error) {
	if !strings.EqualFold(h.Get("Content-Encoding"), "aes128gcm") {
		return notification{}, errUnsupportedEncoding
	}
	ttl, err := strconv.ParseInt(h.Get("TTL"), 10, 64)
	if err != nil || ttl < 0 || ttl > int64(maxTTL/time.Second) {
		return notification{}, errInvalidRequest
	}
	urgency := strings.ToLower(h.Get("Urgency"))
	if !slices.Contains([]string{"", "very-low", "low", "normal", "high"}, urgency) {
		return notification{}, errInvalidRequest
	}
	alert := cmp.Or(strings.ToLower(h.Get("Supaterm-Alert")), "activity")
	text, ok := alertText[alert]
	if !ok {
		return notification{}, errInvalidRequest
	}
	return notification{
		title:  "Supaterm",
		body:   text,
		sound:  true,
		urgent: urgency == "high",
		ttl:    time.Duration(ttl) * time.Second,
		data:   map[string]string{"type": "message", "alert": alert},
	}, nil
}

func (s *Server) sendSubscription(ctx context.Context, g grant, sub subscription, request string) error {
	if !s.devices.Allow(sha256.Sum256([]byte(g.Platform+"\n"+g.Token)), s.now()) {
		return errRateLimited
	}
	return s.deliver(ctx, g, notification{
		title:  "Supaterm",
		body:   "Notifications are on",
		urgent: true,
		ttl:    subscriptionTTL,
		data: map[string]string{
			"type":       "subscription",
			"request":    request,
			"endpoint":   sub.Endpoint,
			"expiresAt":  strconv.FormatInt(sub.ExpiresAt, 10),
			"renewAfter": strconv.FormatInt(sub.RenewAfter, 10),
		},
	})
}

func (s *Server) deliver(ctx context.Context, g grant, n notification) error {
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	res := s.platforms[g.Platform].deliver(ctx, g, n, s.now())
	switch res.outcome {
	case delivered:
		return nil
	case tokenGone:
		return errTokenUnregistered
	case tooLarge:
		return errPayloadTooLarge
	case misconfigured:
		s.log.Error("platform refused the gateway's credentials", "platform", g.Platform, "status", res.status, "reason", res.reason)
		return errGatewayMisconfigured
	default:
		s.log.Warn("platform unavailable", "platform", g.Platform, "status", res.status, "reason", res.reason)
		return errUpstreamUnavailable
	}
}

func (s *Server) target(g grant) (grant, error) {
	switch g.Platform {
	case "apns":
		if g.Environment != Sandbox && g.Environment != Production {
			return g, errInvalidRequest
		}
		if _, ok := s.cfg.APNs.Keys[g.Environment]; !ok {
			return g, errPlatformNotConfigured
		}
		if !slices.Contains(s.cfg.APNs.Topics, g.Topic) {
			return g, errTopicNotAllowed
		}
		g.Token = strings.ToLower(g.Token)
		if !validToken(g.Token, "0123456789abcdef") || len(g.Token)%2 != 0 {
			return g, errInvalidRequest
		}
	case "fcm":
		if s.cfg.FCM == nil {
			return g, errPlatformNotConfigured
		}
		if g.Topic != "" || g.Environment != "" || !validToken(g.Token, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_:") {
			return g, errInvalidRequest
		}
	default:
		return g, errInvalidRequest
	}
	return g, nil
}

func validToken(token, alphabet string) bool {
	return len(token) >= 16 && len(token) <= maxTokenLength && strings.Trim(token, alphabet) == ""
}

func validRequestID(id string) bool {
	return id != "" && len(id) <= maxRequestIDLength && strings.Trim(id, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == ""
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if s.draining.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "draining"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) limitViewers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.viewers.Allow(s.clientIP(r), s.now()) {
			s.reject(w, errRateLimited)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) dashboardStats() dashboard.Stats {
	stats := dashboard.Stats{
		Draining: s.draining.Load(),
		Counts: []dashboard.Count{
			{Label: "Subscriptions issued", Value: s.issued.Load(), Detail: "since start"},
			{Label: "Renewals", Value: s.renewed.Load(), Detail: "since start"},
			{Label: "Revoked grants", Value: int64(s.revoked.size()), Detail: "kept 30 days"},
		},
		ForwardedMessages: s.delivered.Load(),
		ForwardedBytes:    s.deliveredBytes.Load(),
	}
	s.rejectionsMu.Lock()
	defer s.rejectionsMu.Unlock()
	for _, n := range s.rejections {
		stats.Rejected += n
	}
	stats.RejectedByReason = maps.Clone(s.rejections)
	return stats
}

func (s *Server) clientIP(r *http.Request) netip.Addr {
	return admission.ClientIP(r, s.cfg.TrustedProxies)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	body, err := readBody(w, r, maxJSONBody)
	if err != nil {
		return err
	}
	if json.Unmarshal([]byte(body), v) != nil {
		return errInvalidRequest
	}
	return nil
}

func readBody(w http.ResponseWriter, r *http.Request, limit int64) (string, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return "", errPayloadTooLarge
	}
	if err != nil {
		return "", errInvalidRequest
	}
	return string(body), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
