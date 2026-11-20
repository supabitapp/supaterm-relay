package push

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testOrigin = "https://push.example.test"
	testTopic  = "com.supaterm.mobile"
)

var fcmKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

type upstreamRequest struct {
	path   string
	header http.Header
	body   []byte
}

type reply struct {
	status int
	body   string
}

type fakeUpstream struct {
	*httptest.Server
	mu       sync.Mutex
	requests []upstreamRequest
	replies  map[string]reply
}

func newFakeUpstream(t *testing.T, tls bool, route func(*fakeUpstream, upstreamRequest) string) *fakeUpstream {
	t.Helper()
	f := &fakeUpstream{replies: map[string]reply{}}
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req := upstreamRequest{path: r.URL.Path, header: r.Header.Clone(), body: body}
		f.mu.Lock()
		f.requests = append(f.requests, req)
		rep, ok := f.replies[route(f, req)]
		f.mu.Unlock()
		if !ok {
			rep = reply{status: http.StatusOK, body: "{}"}
		}
		w.WriteHeader(rep.status)
		_, _ = io.WriteString(w, rep.body)
	}))
	if tls {
		f.EnableHTTP2 = true
		f.StartTLS()
	} else {
		f.Start()
	}
	t.Cleanup(f.Close)
	return f
}

func (f *fakeUpstream) reply(key string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies[key] = reply{status: status, body: body}
}

func (f *fakeUpstream) last(t *testing.T, pathPrefix string) upstreamRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range slices.Backward(f.requests) {
		if strings.HasPrefix(v.path, pathPrefix) {
			return v
		}
	}
	t.Fatalf("no upstream request to %s", pathPrefix)
	return upstreamRequest{}
}

func (f *fakeUpstream) count(pathPrefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r.path, pathPrefix) {
			n++
		}
	}
	return n
}

type testEnv struct {
	t        *testing.T
	s        *Server
	cfg      Config
	apns     *fakeUpstream
	fcm      *fakeUpstream
	apnsKey  *ecdsa.PrivateKey
	clockMu  sync.Mutex
	clock    time.Time
	nextAddr atomic.Int64
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	e := &testEnv{t: t, clock: time.Unix(1_800_000_000, 0), apnsKey: newKey(t)}
	e.apns = newFakeUpstream(t, true, func(_ *fakeUpstream, r upstreamRequest) string {
		return strings.TrimPrefix(r.path, "/3/device/")
	})
	e.fcm = newFakeUpstream(t, false, func(f *fakeUpstream, r upstreamRequest) string {
		if r.path == "/token" {
			return "token"
		}
		var msg struct {
			Message struct {
				Token string `json:"token"`
			} `json:"message"`
		}
		_ = json.Unmarshal(r.body, &msg)
		return msg.Message.Token
	})
	e.fcm.reply("token", http.StatusOK, `{"access_token":"fcm-access","expires_in":3600}`)
	e.cfg = Config{
		PublicURL:      testOrigin,
		SealKeys:       [][]byte{bytes.Repeat([]byte{7}, 32)},
		RevocationFile: filepath.Join(t.TempDir(), "revocations"),
		APNs: APNsConfig{
			TeamID: "TEAM123456",
			Topics: []string{testTopic},
			Keys:   map[string]APNsKey{Sandbox: {ID: "KEY1234567", Key: e.apnsKey}},
		},
		FCM: &FCMCredential{ProjectID: "supaterm-test", ClientEmail: "push@supaterm-test.iam.example", Key: fcmKey(), TokenURL: e.fcm.URL + "/token"},
	}
	e.start()
	return e
}

func (e *testEnv) start() {
	e.t.Helper()
	if e.s != nil {
		_ = e.s.revoked.close()
	}
	s, err := newServer(e.cfg, slog.New(slog.DiscardHandler), e.now)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = s.revoked.close() })
	apns := s.platforms["apns"].(*apnsClient)
	apns.http = e.apns.Client()
	apns.urls = map[string]string{Sandbox: e.apns.URL, Production: e.apns.URL}
	fcm := s.platforms["fcm"].(*fcmClient)
	fcm.http = e.fcm.Client()
	fcm.sendURL = e.fcm.URL + "/send"
	e.s = s
}

func (e *testEnv) now() time.Time {
	e.clockMu.Lock()
	defer e.clockMu.Unlock()
	return e.clock
}

func (e *testEnv) advance(d time.Duration) {
	e.clockMu.Lock()
	defer e.clockMu.Unlock()
	e.clock = e.clock.Add(d)
}

func (e *testEnv) serve(r *http.Request) *httptest.ResponseRecorder {
	r.RemoteAddr = "192.0.2." + strconv.FormatInt(e.nextAddr.Add(1)%250+1, 10) + ":1234"
	w := httptest.NewRecorder()
	e.s.http.Handler.ServeHTTP(w, r)
	return w
}

func (e *testEnv) post(path string, body string, header http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	maps.Copy(r.Header, header)
	return e.serve(r)
}

type phone struct {
	platform    string
	token       string
	environment string
	topic       string
	management  *ecdsa.PrivateKey
}

func apnsPhone(t *testing.T, token string) phone {
	return phone{platform: "apns", token: token, environment: Sandbox, topic: testTopic, management: newKey(t)}
}

func fcmPhone(t *testing.T, token string) phone {
	return phone{platform: "fcm", token: token, management: newKey(t)}
}

func (e *testEnv) subscribeRequest(p phone, host *ecdsa.PrivateKey) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{
		"platform":      p.platform,
		"token":         p.token,
		"topic":         p.topic,
		"environment":   p.environment,
		"hostKey":       pub(host),
		"managementKey": pub(p.management),
		"request":       "req-1",
	})
	return e.post("/v1/subscriptions", string(body), nil)
}

func (e *testEnv) subscribe(p phone, host *ecdsa.PrivateKey) subscription {
	e.t.Helper()
	if w := e.subscribeRequest(p, host); w.Code != http.StatusAccepted {
		e.t.Fatalf("subscribe: %d %s", w.Code, w.Body)
	}
	return e.delivered(p).subscription(e.t)
}

type pushed map[string]any

func (e *testEnv) delivered(p phone) pushed {
	e.t.Helper()
	var payload pushed
	if p.platform == "apns" {
		if err := json.Unmarshal(e.apns.last(e.t, "/3/device/"+p.token).body, &payload); err != nil {
			e.t.Fatal(err)
		}
		return payload
	}
	var msg struct {
		Message struct {
			Token string         `json:"token"`
			Data  map[string]any `json:"data"`
		} `json:"message"`
	}
	if err := json.Unmarshal(e.fcm.last(e.t, "/send").body, &msg); err != nil || msg.Message.Token != p.token {
		e.t.Fatalf("fcm message for %s: %v", msg.Message.Token, err)
	}
	return msg.Message.Data
}

func (p pushed) subscription(t *testing.T) subscription {
	t.Helper()
	if p["type"] != "subscription" || p["request"] != "req-1" {
		t.Fatalf("not a subscription push: %v", p)
	}
	expires, _ := p["expiresAt"].(string)
	renew, _ := p["renewAfter"].(string)
	return subscription{Endpoint: p["endpoint"].(string), ExpiresAt: atoi(t, expires), RenewAfter: atoi(t, renew)}
}

func (e *testEnv) send(endpoint string, host *ecdsa.PrivateKey, header http.Header, body string) *httptest.ResponseRecorder {
	h := http.Header{
		"Authorization":    {vapid(e.t, host, testOrigin, e.now().Add(time.Hour))},
		"Content-Encoding": {"aes128gcm"},
		"Ttl":              {"60"},
		"Urgency":          {"high"},
	}
	for k, v := range header {
		if v == nil {
			h.Del(k)
		} else {
			h[http.CanonicalHeaderKey(k)] = v
		}
	}
	return e.post(strings.TrimPrefix(endpoint, testOrigin), body, h)
}

func (e *testEnv) phoneRequest(p phone, action, endpoint string, extra map[string]any) *httptest.ResponseRecorder {
	claims := map[string]any{"aud": testOrigin, "act": action, "iat": e.now().Unix(), "exp": e.now().Add(time.Minute).Unix(), "endpoint": endpoint}
	maps.Copy(claims, extra)
	return e.post("/v1/subscriptions/"+action, sign(e.t, p.management, claims), nil)
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func pub(key *ecdsa.PrivateKey) string {
	raw, err := key.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func sign(t *testing.T, key *ecdsa.PrivateKey, claims any) string {
	t.Helper()
	token, err := signES256(key, map[string]string{"typ": "JWT", "alg": "ES256"}, claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func vapid(t *testing.T, key *ecdsa.PrivateKey, aud string, exp time.Time) string {
	t.Helper()
	return "vapid t=" + sign(t, key, map[string]any{"aud": aud, "exp": exp.Unix(), "sub": "mailto:host@example.test"}) + ", k=" + pub(key)
}

func verifyRS256(t *testing.T, key *rsa.PublicKey, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("assertion signature: %v", err)
	}
	var claims map[string]any
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(payload, &claims)
	return claims
}

func errorCode(w *httptest.ResponseRecorder) string {
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return body.Error
}

func expect(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status || errorCode(w) != code {
		t.Fatalf("got %d %s, want %d %q", w.Code, strings.TrimSpace(w.Body.String()), status, code)
	}
}

func form(t *testing.T, body []byte) url.Values {
	t.Helper()
	v, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func atoi(t *testing.T, s string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		t.Fatalf("not a number: %q", s)
	}
	return n
}
