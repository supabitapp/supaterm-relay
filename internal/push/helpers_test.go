package push

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const testTopic = "com.supabit.supaterm"

var testEpoch = time.UnixMilli(1_791_840_000_000)

type apnsCall struct {
	Token  string
	Header http.Header
	Body   []byte
}

type fakeAPNs struct {
	*httptest.Server
	mu      sync.Mutex
	calls   []apnsCall
	replies map[string]apnsReply
}

type apnsReply struct {
	status int
	reason string
}

func newFakeAPNs(t *testing.T) *fakeAPNs {
	f := &fakeAPNs{replies: map[string]apnsReply{}}
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("APNs request over %s, want HTTP/2", r.Proto)
		}
		token := strings.TrimPrefix(r.URL.Path, "/3/device/")
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.calls = append(f.calls, apnsCall{Token: token, Header: r.Header.Clone(), Body: body})
		reply, ok := f.replies[token]
		f.mu.Unlock()
		if !ok {
			reply = apnsReply{status: http.StatusOK}
		}
		w.WriteHeader(reply.status)
		if reply.reason != "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"reason": reply.reason})
		}
	}))
	f.EnableHTTP2 = true
	f.StartTLS()
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAPNs) reply(token string, status int, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies[token] = apnsReply{status, reason}
}

func (f *fakeAPNs) last(t *testing.T) apnsCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("no APNs requests")
	}
	return f.calls[len(f.calls)-1]
}

func (f *fakeAPNs) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type gateway struct {
	t     *testing.T
	s     *Server
	store *Store
	apns  *fakeAPNs
	key   *ecdsa.PrivateKey
	now   time.Time
}

func newGateway(t *testing.T) *gateway {
	t.Helper()
	fake := newFakeAPNs(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(t.TempDir(), "push.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := Config{
		TeamID: "TEAM123456",
		Topics: []string{testTopic},
		Credentials: map[string]Credential{
			Sandbox:    {KeyID: "SANDBOXKEY", Key: key, URL: fake.URL},
			Production: {KeyID: "PRODKEY", Key: key, URL: fake.URL},
		},
	}
	g := &gateway{t: t, store: store, apns: fake, key: key, now: testEpoch}
	g.s = New(cfg, store, fake.Client(), slog.New(slog.DiscardHandler))
	g.s.now = func() time.Time { return g.now }
	return g
}

func (g *gateway) advance(d time.Duration) {
	g.now = g.now.Add(d)
}

func (g *gateway) serve(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	g.s.Handler().ServeHTTP(w, r)
	return w
}

func (g *gateway) call(method, path, owner string, body any) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	if owner != "" {
		r.Header.Set("Authorization", "Bearer "+owner)
	}
	return g.serve(r)
}

func (g *gateway) signed(host ed25519.PrivateKey, method, path string, body []byte, at time.Time) *http.Request {
	stamp := strconv.FormatInt(at.UnixMilli(), 10)
	digest := sha256.Sum256(body)
	message := "supaterm-push-request-v1\n" + method + "\n" + path + "\n" + stamp + "\n" + hex.EncodeToString(digest[:])
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("supaterm-push-key", b64u.EncodeToString(host.Public().(ed25519.PublicKey)))
	r.Header.Set("supaterm-push-timestamp", stamp)
	r.Header.Set("supaterm-push-signature", b64u.EncodeToString(ed25519.Sign(host, []byte(message))))
	return r
}

func (g *gateway) send(host ed25519.PrivateKey, handle string) *httptest.ResponseRecorder {
	return g.serve(g.signed(host, http.MethodPost, "/v1/send", sendBody(handle, g.now), g.now))
}

func sendBody(handle string, now time.Time) []byte {
	b, _ := json.Marshal(map[string]any{
		"handle":     handle,
		"payload":    map[string]any{"v": 1, "ciphertext": "abc"},
		"expiration": now.Add(10 * time.Minute).Unix(),
		"priority":   10,
		"collapseId": "thread_1",
	})
	return b
}

func token(n byte) string {
	return strings.Repeat(hex.EncodeToString([]byte{n}), 32)
}

type challenge struct {
	EnrollmentID string `json:"enrollmentId"`
	Code         string `json:"code"`
}

func (g *gateway) startEnrollment(tok, installationID, owner string) challenge {
	g.t.Helper()
	body := map[string]string{"token": tok, "topic": testTopic, "environment": Sandbox}
	if installationID != "" {
		body["installationId"] = installationID
	}
	w := g.call(http.MethodPost, "/v1/enrollments", owner, body)
	if w.Code != http.StatusCreated {
		g.t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	var push struct {
		Challenge challenge `json:"supatermChallenge"`
	}
	if err := json.Unmarshal(g.apns.last(g.t).Body, &push); err != nil {
		g.t.Fatal(err)
	}
	return push.Challenge
}

type confirmation struct {
	InstallationID string `json:"installationId"`
	OwnerToken     string `json:"ownerToken"`
}

func (g *gateway) confirm(c challenge) confirmation {
	g.t.Helper()
	w := g.call(http.MethodPost, "/v1/enrollments/"+c.EnrollmentID+"/confirm", "", map[string]string{"code": c.Code})
	if w.Code != http.StatusOK {
		g.t.Fatalf("confirm: %d %s", w.Code, w.Body)
	}
	var out confirmation
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func (g *gateway) enroll(tok string) confirmation {
	g.t.Helper()
	return g.confirm(g.startEnrollment(tok, "", ""))
}

func (g *gateway) mint(in confirmation, host ed25519.PrivateKey) string {
	g.t.Helper()
	w := g.call(http.MethodPost, "/v1/installations/"+in.InstallationID+"/handles", in.OwnerToken,
		map[string]string{"hostKey": b64u.EncodeToString(host.Public().(ed25519.PublicKey))})
	if w.Code != http.StatusCreated {
		g.t.Fatalf("mint handle: %d %s", w.Code, w.Body)
	}
	var out struct {
		Handle string `json:"handle"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out.Handle
}

func hostKey(t *testing.T) ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
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
