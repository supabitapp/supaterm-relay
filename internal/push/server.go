package push

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/supabitapp/supaterm-relay/internal/admission"
)

const (
	maxBodyBytes      = 8 << 10
	enrollmentTTL     = 10 * time.Minute
	challengeTTL      = 600 * time.Second
	maxCodeAttempts   = 5
	maxHandles        = 64
	signatureWindow   = 300 * time.Second
	maxExpiration     = 24*time.Hour + signatureWindow
	requestSignature  = "supaterm-push-request-v1"
	healthTimeout     = 2 * time.Second
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
)

var (
	b64u       = base64.RawURLEncoding
	loopback   = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	collapseID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

type Server struct {
	store   *Store
	apns    *apnsClient
	log     *slog.Logger
	now     func() time.Time
	topics  map[string]bool
	replays *replayCache
	http    *http.Server

	enrollmentsPerIP   *limiter
	challengesPerToken *limiter
	sendsPerHandle     *limiter
	sendsPerHost       *limiter
	sendsPerInstall    *limiter
}

func New(cfg Config, store *Store, client *http.Client, log *slog.Logger) *Server {
	s := &Server{
		store:   store,
		log:     log,
		now:     time.Now,
		topics:  map[string]bool{},
		replays: newReplayCache(),

		enrollmentsPerIP:   newLimiter(20, time.Hour, 20),
		challengesPerToken: newLimiter(5, time.Hour, 5),
		sendsPerHandle:     newLimiter(30, time.Minute, 10),
		sendsPerHost:       newLimiter(600, time.Minute, 60),
		sendsPerInstall:    newLimiter(120, time.Minute, 20),
	}
	s.apns = newAPNsClient(client, cfg.TeamID, cfg.Credentials, func() time.Time { return s.now() })
	for _, topic := range cfg.Topics {
		s.topics[topic] = true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	s.route(mux, "POST /v1/enrollments", s.handleEnroll)
	s.route(mux, "POST /v1/enrollments/{enrollmentId}/confirm", s.handleConfirm)
	s.route(mux, "GET /v1/installations/{installationId}", s.handleInstallation)
	s.route(mux, "DELETE /v1/installations/{installationId}", s.handleDeleteInstallation)
	s.route(mux, "POST /v1/installations/{installationId}/handles", s.handleCreateHandle)
	s.route(mux, "DELETE /v1/installations/{installationId}/handles/{handle}", s.handleDeleteOwnedHandle)
	s.route(mux, "POST /v1/send", s.handleSend)
	s.route(mux, "DELETE /v1/handles/{handle}", s.handleDeleteHostHandle)
	s.http = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return s
}

func (s *Server) Handler() http.Handler {
	return s.http.Handler
}

func (s *Server) Serve(ln net.Listener) error {
	return s.http.Serve(ln)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

type apiError struct {
	status     int
	code       string
	message    string
	retryAfter time.Duration
}

func (e *apiError) Error() string {
	return e.code + ": " + e.message
}

func fail(status int, code, message string) *apiError {
	return &apiError{status: status, code: code, message: message}
}

func invalid(message string) *apiError {
	return fail(http.StatusBadRequest, "invalid_request", message)
}

func rateLimited(wait time.Duration) *apiError {
	e := fail(http.StatusTooManyRequests, "rate_limited", "too many requests")
	e.retryAfter = wait
	return e
}

var (
	errUnauthorized = fail(http.StatusUnauthorized, "unauthorized", "missing or invalid credentials")
	errNotFound     = fail(http.StatusNotFound, "not_found", "not found")
	errGone         = fail(http.StatusGone, "gone", "the handle can no longer deliver")
	errAPNs         = fail(http.StatusBadGateway, "apns_unavailable", "APNs is unavailable; retry later")
	errCredential   = fail(http.StatusServiceUnavailable, "gateway_unavailable", "the gateway cannot reach APNs; retry later")
)

func (s *Server) route(mux *http.ServeMux, pattern string, h func(http.ResponseWriter, *http.Request) error) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		err := h(w, r)
		if err == nil {
			return
		}
		var e *apiError
		if !errors.As(err, &e) {
			s.log.Error("request failed", "route", pattern, "error", err)
			e = fail(http.StatusInternalServerError, "internal", "internal error")
		}
		if e.retryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(e.retryAfter.Seconds()))))
		}
		writeJSON(w, e.status, map[string]string{"error": e.code, "message": e.message})
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
	defer cancel()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.store.Ping(ctx); err != nil {
		s.log.Error("health check failed", "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "unavailable")
		return
	}
	_, _ = io.WriteString(w, "ok")
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Token          string `json:"token"`
		Topic          string `json:"topic"`
		Environment    string `json:"environment"`
		InstallationID string `json:"installationId"`
	}
	if err := decodeBody(r, &req); err != nil {
		return err
	}
	if !validToken(req.Token) {
		return invalid("token must be 64 to 200 lowercase hex characters")
	}
	if req.Environment != Sandbox && req.Environment != Production {
		return invalid(`environment must be "sandbox" or "production"`)
	}
	if req.InstallationID != "" {
		if _, err := s.owner(r, req.InstallationID); err != nil {
			return err
		}
	}
	if !s.topics[req.Topic] {
		return fail(http.StatusForbidden, "topic_not_allowed", "this gateway does not serve the topic")
	}
	if !s.apns.supports(req.Environment) {
		return invalid("this gateway has no APNs key for the environment")
	}
	now := s.now()
	tokenHash := sha256.Sum256([]byte(req.Token))
	if wait := take(now,
		quota{s.enrollmentsPerIP, clientNetwork(r)},
		quota{s.challengesPerToken, string(tokenHash[:])},
	); wait > 0 {
		return rateLimited(wait)
	}

	code := randomBytes(16)
	codeHash := sha256.Sum256(code)
	e := Enrollment{
		ID:             b64u.EncodeToString(randomBytes(16)),
		Token:          req.Token,
		Topic:          req.Topic,
		Environment:    req.Environment,
		InstallationID: req.InstallationID,
		CodeHash:       codeHash[:],
		ExpiresAt:      now.Add(enrollmentTTL),
	}
	ctx := context.WithoutCancel(r.Context())
	if err := s.store.CreateEnrollment(ctx, e, now); err != nil {
		return err
	}
	res := s.apns.send(ctx, apnsRequest{
		Environment: e.Environment,
		Token:       e.Token,
		Topic:       e.Topic,
		Priority:    10,
		Expiration:  now.Add(challengeTTL).Unix(),
		Body:        challengeBody(e.ID, b64u.EncodeToString(code)),
	})
	if res.Outcome != apnsAccepted {
		s.logAPNs("challenge", e.Environment, res)
		if err := s.store.DeleteEnrollment(ctx, e.ID); err != nil {
			return err
		}
	}
	switch res.Outcome {
	case apnsAccepted:
		writeJSON(w, http.StatusCreated, map[string]any{"enrollmentId": e.ID, "expiresAt": e.ExpiresAt.UnixMilli()})
		return nil
	case apnsGone:
		return fail(http.StatusGone, "token_rejected", "APNs rejected the device token")
	case apnsCredential:
		return errCredential
	default:
		return errAPNs
	}
}

func (s *Server) handleConfirm(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeBody(r, &req); err != nil {
		return err
	}
	code, ok := decodeB64(req.Code, 16)
	if !ok {
		return invalid("code must be 16 base64url bytes")
	}
	ctx := r.Context()
	now := s.now()
	e, err := s.store.Enrollment(ctx, r.PathValue("enrollmentId"), now)
	if errors.Is(err, ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	codeHash := sha256.Sum256(code)
	if subtle.ConstantTimeCompare(codeHash[:], e.CodeHash) != 1 {
		if err := s.store.FailEnrollment(ctx, e.ID, maxCodeAttempts); err != nil {
			return err
		}
		return fail(http.StatusForbidden, "invalid_code", "the code does not match")
	}

	var fresh Installation
	var ownerToken string
	if e.InstallationID == "" {
		raw := randomBytes(32)
		ownerHash := sha256.Sum256(raw)
		fresh = Installation{ID: b64u.EncodeToString(randomBytes(16)), OwnerTokenHash: ownerHash[:]}
		ownerToken = b64u.EncodeToString(raw)
	}
	id, err := s.store.ConfirmEnrollment(ctx, e, fresh, now)
	if errors.Is(err, ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	body := map[string]string{"installationId": id}
	if ownerToken != "" {
		body["ownerToken"] = ownerToken
	}
	writeJSON(w, http.StatusOK, body)
	return nil
}

func (s *Server) handleInstallation(w http.ResponseWriter, r *http.Request) error {
	in, err := s.owner(r, r.PathValue("installationId"))
	if err != nil {
		return err
	}
	n, err := s.store.HandleCount(r.Context(), in.ID)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"installationId": in.ID,
		"topic":          in.Topic,
		"environment":    in.Environment,
		"handles":        n,
	})
	return nil
}

func (s *Server) handleDeleteInstallation(w http.ResponseWriter, r *http.Request) error {
	in, err := s.owner(r, r.PathValue("installationId"))
	if err != nil {
		return err
	}
	if err := s.store.DeleteInstallation(r.Context(), in.ID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) handleCreateHandle(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		HostKey string `json:"hostKey"`
	}
	if err := decodeBody(r, &req); err != nil {
		return err
	}
	hostKey, ok := decodeB64(req.HostKey, ed25519.PublicKeySize)
	if !ok {
		return invalid("hostKey must be a 32-byte base64url Ed25519 public key")
	}
	in, err := s.owner(r, r.PathValue("installationId"))
	if err != nil {
		return err
	}
	h := Handle{Handle: b64u.EncodeToString(randomBytes(16)), InstallationID: in.ID, HostKey: hostKey}
	err = s.store.CreateHandle(r.Context(), h, maxHandles, s.now())
	if errors.Is(err, ErrTooManyHandles) {
		return fail(http.StatusConflict, "too_many_handles", "the installation has the maximum number of handles")
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]string{"handle": h.Handle})
	return nil
}

func (s *Server) handleDeleteOwnedHandle(w http.ResponseWriter, r *http.Request) error {
	in, err := s.owner(r, r.PathValue("installationId"))
	if err != nil {
		return err
	}
	err = s.store.DeleteInstallationHandle(r.Context(), in.ID, r.PathValue("handle"))
	if errors.Is(err, ErrNotFound) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) error {
	host, err := s.host(r)
	if err != nil {
		return err
	}
	var req struct {
		Handle     string          `json:"handle"`
		Payload    json.RawMessage `json:"payload"`
		Expiration int64           `json:"expiration"`
		Priority   int             `json:"priority"`
		CollapseID string          `json:"collapseId"`
	}
	if err := json.Unmarshal(host.body, &req); err != nil {
		return invalid("body must be a JSON object")
	}
	now := s.now()
	switch {
	case !validHandle(req.Handle):
		return invalid("handle must be 16 base64url bytes")
	case !isObject(req.Payload):
		return invalid("payload must be a JSON object")
	case req.Expiration <= 0 || req.Expiration > now.Add(maxExpiration).Unix():
		return invalid("expiration must be a unix time at most 24 hours ahead")
	case req.Priority != 10 && req.Priority != 5:
		return invalid("priority must be 10 or 5")
	case req.CollapseID != "" && !collapseID.MatchString(req.CollapseID):
		return invalid("collapseId must be at most 64 characters of [A-Za-z0-9_-]")
	}
	body, err := alertBody(req.Payload)
	if err != nil {
		return invalid("payload is too large for APNs")
	}

	ctx := context.WithoutCancel(r.Context())
	handle, in, err := s.store.Target(ctx, req.Handle)
	if errors.Is(err, ErrNotFound) || err == nil && !bytes.Equal(handle.HostKey, host.key) {
		return errGone
	}
	if err != nil {
		return err
	}
	if wait := take(now,
		quota{s.sendsPerHandle, handle.Handle},
		quota{s.sendsPerHost, string(host.key)},
		quota{s.sendsPerInstall, in.ID},
	); wait > 0 {
		return rateLimited(wait)
	}
	if err := s.claim(host); err != nil {
		return err
	}
	res := s.apns.send(ctx, apnsRequest{
		Environment: in.Environment,
		Token:       in.Token,
		Topic:       in.Topic,
		Priority:    req.Priority,
		Expiration:  req.Expiration,
		CollapseID:  req.CollapseID,
		Body:        body,
	})
	if res.Outcome != apnsAccepted {
		s.logAPNs("alert", in.Environment, res)
	}
	switch res.Outcome {
	case apnsAccepted:
		writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
		return nil
	case apnsGone:
		if err := s.store.DeleteInstallation(ctx, in.ID); err != nil {
			return err
		}
		return errGone
	case apnsCredential:
		return errCredential
	default:
		return errAPNs
	}
}

func (s *Server) handleDeleteHostHandle(w http.ResponseWriter, r *http.Request) error {
	host, err := s.host(r)
	if err != nil {
		return err
	}
	handle, _, err := s.store.Target(r.Context(), r.PathValue("handle"))
	if errors.Is(err, ErrNotFound) || err == nil && !bytes.Equal(handle.HostKey, host.key) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	if err := s.claim(host); err != nil {
		return err
	}
	if err := s.store.DeleteHandle(r.Context(), handle.Handle); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) owner(r *http.Request, installationID string) (Installation, error) {
	scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	raw, ok := decodeB64(token, 32)
	if !strings.EqualFold(scheme, "bearer") || !ok {
		return Installation{}, errUnauthorized
	}
	in, err := s.store.Installation(r.Context(), installationID)
	if errors.Is(err, ErrNotFound) {
		return in, errNotFound
	}
	if err != nil {
		return in, err
	}
	sum := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare(sum[:], in.OwnerTokenHash) != 1 {
		return in, errUnauthorized
	}
	return in, nil
}

type hostRequest struct {
	key       ed25519.PublicKey
	signature string
	until     time.Time
	body      []byte
}

// host verifies the request signature. It leaves the replay check to claim
// so that only requests addressed to the signer's own handles occupy the
// replay cache; anyone can mint a key and sign.
func (s *Server) host(r *http.Request) (hostRequest, error) {
	body, err := readBody(r)
	if err != nil {
		return hostRequest{}, err
	}
	key, keyOK := decodeB64(r.Header.Get("Supaterm-Push-Key"), ed25519.PublicKeySize)
	sig, sigOK := decodeB64(r.Header.Get("Supaterm-Push-Signature"), ed25519.SignatureSize)
	stamp := r.Header.Get("Supaterm-Push-Timestamp")
	ms, err := strconv.ParseInt(stamp, 10, 64)
	if !keyOK || !sigOK || err != nil {
		return hostRequest{}, errUnauthorized
	}
	signed := time.UnixMilli(ms)
	if skew := s.now().Sub(signed); skew > signatureWindow || skew < -signatureWindow {
		return hostRequest{}, fail(http.StatusUnauthorized, "unauthorized", "timestamp is outside the accepted window")
	}
	digest := sha256.Sum256(body)
	message := requestSignature + "\n" + r.Method + "\n" + r.URL.EscapedPath() + "\n" + stamp + "\n" + hex.EncodeToString(digest[:])
	if !ed25519.Verify(key, []byte(message), sig) {
		return hostRequest{}, errUnauthorized
	}
	return hostRequest{key: key, signature: string(sig), until: signed.Add(signatureWindow), body: body}, nil
}

func (s *Server) claim(h hostRequest) error {
	if !s.replays.add(h.signature, h.until, s.now()) {
		return fail(http.StatusUnauthorized, "unauthorized", "the request signature was already used")
	}
	return nil
}

func (s *Server) logAPNs(kind, env string, res apnsResult) {
	s.log.Warn("apns rejected push", "push", kind, "environment", env, "status", res.Status, "reason", res.Reason)
}

func clientNetwork(r *http.Request) string {
	return admission.ClientKey(admission.ClientIP(r, loopback)).String()
}

func readBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err != nil {
		return nil, invalid("body must be at most 8 KiB")
	}
	return body, nil
}

func decodeBody(r *http.Request, v any) error {
	body, err := readBody(r)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return invalid("body must be a JSON object")
	}
	return nil
}

func decodeB64(s string, size int) ([]byte, bool) {
	if b64u.EncodedLen(size) != len(s) {
		return nil, false
	}
	b, err := b64u.Strict().DecodeString(s)
	return b, err == nil && len(b) == size
}

func validHandle(s string) bool {
	_, ok := decodeB64(s, 16)
	return ok
}

func validToken(s string) bool {
	if len(s) < 64 || len(s) > 200 || len(s)%2 != 0 {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isObject(raw json.RawMessage) bool {
	raw = bytes.TrimLeft(raw, " \t\r\n")
	return len(raw) > 0 && raw[0] == '{'
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
