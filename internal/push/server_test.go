package push

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEnrollmentSendsChallengeAndCreatesInstallation(t *testing.T) {
	g := newGateway(t)
	w := g.call(http.MethodPost, "/v1/enrollments", "", map[string]string{"token": token(1), "topic": testTopic, "environment": Sandbox})
	if w.Code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	var created struct {
		EnrollmentID string `json:"enrollmentId"`
		ExpiresAt    int64  `json:"expiresAt"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created.ExpiresAt != g.now.Add(10*time.Minute).UnixMilli() {
		t.Fatalf("expiresAt = %d", created.ExpiresAt)
	}

	call := g.apns.last(t)
	for name, want := range map[string]string{
		"apns-push-type":  "alert",
		"apns-topic":      testTopic,
		"apns-priority":   "10",
		"apns-expiration": "1791840600",
	} {
		if got := call.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	var push struct {
		APS struct {
			Alert          apsAlert `json:"alert"`
			MutableContent int      `json:"mutable-content"`
		} `json:"aps"`
		Challenge challenge `json:"supatermChallenge"`
	}
	if err := json.Unmarshal(call.Body, &push); err != nil {
		t.Fatal(err)
	}
	if push.APS.Alert.Body != "Finishing notification setup" || push.APS.MutableContent != 1 || push.Challenge.EnrollmentID != created.EnrollmentID {
		t.Fatalf("challenge push = %s", call.Body)
	}
	if _, ok := decodeB64(push.Challenge.Code, 16); !ok {
		t.Fatalf("challenge code %q is not 16 base64url bytes", push.Challenge.Code)
	}

	in := g.confirm(push.Challenge)
	if in.InstallationID == "" || in.OwnerToken == "" {
		t.Fatalf("confirmation = %+v", in)
	}
	w = g.call(http.MethodGet, "/v1/installations/"+in.InstallationID, in.OwnerToken, nil)
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != http.StatusOK || got["topic"] != testTopic || got["environment"] != Sandbox || got["handles"] != 0.0 {
		t.Fatalf("installation: %d %v", w.Code, got)
	}
	expect(t, g.call(http.MethodPost, "/v1/enrollments/"+push.Challenge.EnrollmentID+"/confirm", "", map[string]string{"code": push.Challenge.Code}),
		http.StatusNotFound, "not_found")
}

func TestEnrollmentValidation(t *testing.T) {
	g := newGateway(t)
	cases := []struct {
		body   map[string]string
		status int
		code   string
	}{
		{map[string]string{"token": "ABCD" + token(1)[4:], "topic": testTopic, "environment": Sandbox}, 400, "invalid_request"},
		{map[string]string{"token": token(1)[:62], "topic": testTopic, "environment": Sandbox}, 400, "invalid_request"},
		{map[string]string{"token": token(1), "topic": testTopic, "environment": "staging"}, 400, "invalid_request"},
		{map[string]string{"token": token(1), "topic": "com.example.other", "environment": Sandbox}, 403, "topic_not_allowed"},
		{map[string]string{"token": token(1), "topic": testTopic, "environment": Sandbox, "installationId": "nope"}, 401, "unauthorized"},
	}
	for _, c := range cases {
		expect(t, g.call(http.MethodPost, "/v1/enrollments", "", c.body), c.status, c.code)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/enrollments", strings.NewReader(`{"token":"`+strings.Repeat("a", maxBodyBytes)+`"}`))
	expect(t, g.serve(r), http.StatusBadRequest, "invalid_request")
	if g.apns.count() != 0 {
		t.Fatal("invalid enrollments reached APNs")
	}
}

func TestConfirmDeletesEnrollmentAfterFiveWrongCodes(t *testing.T) {
	g := newGateway(t)
	c := g.startEnrollment(token(1), "", "")
	wrong := b64u.EncodeToString(make([]byte, 16))
	path := "/v1/enrollments/" + c.EnrollmentID + "/confirm"
	for range maxCodeAttempts {
		expect(t, g.call(http.MethodPost, path, "", map[string]string{"code": wrong}), http.StatusForbidden, "invalid_code")
	}
	expect(t, g.call(http.MethodPost, path, "", map[string]string{"code": c.Code}), http.StatusNotFound, "not_found")
}

func TestConfirmRejectsExpiredEnrollment(t *testing.T) {
	g := newGateway(t)
	c := g.startEnrollment(token(1), "", "")
	g.advance(enrollmentTTL)
	expect(t, g.call(http.MethodPost, "/v1/enrollments/"+c.EnrollmentID+"/confirm", "", map[string]string{"code": c.Code}),
		http.StatusNotFound, "not_found")
}

func TestRotationKeepsInstallationAndHandles(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	in := g.enroll(token(1))
	handle := g.mint(in, host)

	expect(t, g.call(http.MethodPost, "/v1/enrollments", "", map[string]string{
		"token": token(2), "topic": testTopic, "environment": Sandbox, "installationId": in.InstallationID,
	}), http.StatusUnauthorized, "unauthorized")
	other := g.enroll(token(3))
	expect(t, g.call(http.MethodPost, "/v1/enrollments", other.OwnerToken, map[string]string{
		"token": token(2), "topic": testTopic, "environment": Sandbox, "installationId": in.InstallationID,
	}), http.StatusUnauthorized, "unauthorized")

	rotated := g.confirm(g.startEnrollment(token(2), in.InstallationID, in.OwnerToken))
	if rotated.InstallationID != in.InstallationID || rotated.OwnerToken != "" {
		t.Fatalf("rotation = %+v", rotated)
	}
	if w := g.send(host, handle); w.Code != http.StatusOK {
		t.Fatalf("send after rotation: %d %s", w.Code, w.Body)
	}
	if got := g.apns.last(t).Token; got != token(2) {
		t.Fatalf("delivered to %s, want the rotated token", got)
	}
}

func TestConfirmRetiresOtherInstallationsWithTheSameToken(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	old := g.enroll(token(1))
	oldHandle := g.mint(old, host)
	fresh := g.enroll(token(1))
	if fresh.InstallationID == old.InstallationID {
		t.Fatal("reinstall reused the installation")
	}
	expect(t, g.call(http.MethodGet, "/v1/installations/"+old.InstallationID, old.OwnerToken, nil), http.StatusNotFound, "not_found")
	expect(t, g.send(host, oldHandle), http.StatusGone, "gone")

	rotating := g.enroll(token(2))
	g.confirm(g.startEnrollment(token(1), rotating.InstallationID, rotating.OwnerToken))
	expect(t, g.call(http.MethodGet, "/v1/installations/"+fresh.InstallationID, fresh.OwnerToken, nil), http.StatusNotFound, "not_found")
	if w := g.call(http.MethodGet, "/v1/installations/"+rotating.InstallationID, rotating.OwnerToken, nil); w.Code != http.StatusOK {
		t.Fatalf("rotated installation: %d", w.Code)
	}
}

func TestEnrollmentMapsAPNsRejections(t *testing.T) {
	g := newGateway(t)
	cases := []struct {
		status int
		reason string
		want   int
		code   string
	}{
		{400, "BadDeviceToken", 410, "token_rejected"},
		{400, "DeviceTokenNotForTopic", 410, "token_rejected"},
		{410, "Unregistered", 410, "token_rejected"},
		{503, "ServiceUnavailable", 502, "apns_unavailable"},
		{403, "InvalidProviderToken", 503, "gateway_unavailable"},
	}
	for i, c := range cases {
		tok := token(byte(i + 1))
		g.apns.reply(tok, c.status, c.reason)
		expect(t, g.call(http.MethodPost, "/v1/enrollments", "", map[string]string{"token": tok, "topic": testTopic, "environment": Sandbox}), c.want, c.code)
	}
}

func TestHandleLifecycle(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	in := g.enroll(token(1))
	handle := g.mint(in, host)
	base := "/v1/installations/" + in.InstallationID + "/handles"

	expect(t, g.call(http.MethodPost, base, in.OwnerToken, map[string]string{"hostKey": "short"}), http.StatusBadRequest, "invalid_request")
	expect(t, g.call(http.MethodPost, base, "", map[string]string{"hostKey": b64u.EncodeToString(make([]byte, 32))}), http.StatusUnauthorized, "unauthorized")
	for range maxHandles - 1 {
		g.advance(2 * time.Minute)
		g.mint(in, hostKey(t))
	}
	expect(t, g.call(http.MethodPost, base, in.OwnerToken, map[string]string{"hostKey": b64u.EncodeToString(make([]byte, 32))}), http.StatusConflict, "too_many_handles")

	if w := g.call(http.MethodDelete, base+"/"+handle, in.OwnerToken, nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete handle: %d", w.Code)
	}
	expect(t, g.call(http.MethodDelete, base+"/"+handle, in.OwnerToken, nil), http.StatusNotFound, "not_found")
	expect(t, g.send(host, handle), http.StatusGone, "gone")

	handle = g.mint(in, host)
	if w := g.call(http.MethodDelete, "/v1/installations/"+in.InstallationID, in.OwnerToken, nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete installation: %d", w.Code)
	}
	expect(t, g.send(host, handle), http.StatusGone, "gone")
	expect(t, g.call(http.MethodGet, "/v1/installations/"+in.InstallationID, in.OwnerToken, nil), http.StatusNotFound, "not_found")
}

func TestSendDeliversAlert(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	handle := g.mint(g.enroll(token(1)), host)
	w := g.send(host, handle)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"status":"accepted"}` {
		t.Fatalf("send: %d %s", w.Code, w.Body)
	}
	call := g.apns.last(t)
	want := `{"aps":{"alert":{"title":"Supaterm","body":"New activity"},"sound":"default","mutable-content":1},"supaterm":{"ciphertext":"abc","v":1}}`
	if string(call.Body) != want {
		t.Fatalf("alert body = %s", call.Body)
	}
	for name, want := range map[string]string{
		"apns-push-type":   "alert",
		"apns-topic":       testTopic,
		"apns-priority":    "10",
		"apns-expiration":  "1791840600",
		"apns-collapse-id": "thread_1",
	} {
		if got := call.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestSendRejectsAnotherHostsHandle(t *testing.T) {
	g := newGateway(t)
	owner, intruder := hostKey(t), hostKey(t)
	handle := g.mint(g.enroll(token(1)), owner)
	before := g.apns.count()
	mismatch := g.send(intruder, handle)
	unknown := g.send(owner, b64u.EncodeToString(make([]byte, 16)))
	expect(t, mismatch, http.StatusGone, "gone")
	if mismatch.Body.String() != unknown.Body.String() {
		t.Fatalf("mismatch %q and unknown %q responses differ", mismatch.Body, unknown.Body)
	}
	if g.apns.count() != before {
		t.Fatal("a mismatched host reached APNs")
	}
	if w := g.send(owner, handle); w.Code != http.StatusOK {
		t.Fatalf("owner send: %d", w.Code)
	}
}

func TestSendRetiresRejectedToken(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	in := g.enroll(token(1))
	handle := g.mint(in, host)
	g.apns.reply(token(1), http.StatusGone, "Unregistered")
	expect(t, g.send(host, handle), http.StatusGone, "gone")
	expect(t, g.call(http.MethodGet, "/v1/installations/"+in.InstallationID, in.OwnerToken, nil), http.StatusNotFound, "not_found")
}

func TestRejectionOfReplacedTokenKeepsInstallation(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	in := g.enroll(token(1))
	handle := g.mint(in, host)
	g.apns.reply(token(1), http.StatusGone, "Unregistered")
	gate := g.apns.hold(t, token(1))
	sent := make(chan *httptest.ResponseRecorder)
	go func() { sent <- g.send(host, handle) }()
	<-gate.arrived
	g.confirm(g.startEnrollment(token(2), in.InstallationID, in.OwnerToken))
	gate.release()
	expect(t, <-sent, http.StatusBadGateway, "apns_unavailable")

	g.advance(time.Millisecond)
	if w := g.send(host, handle); w.Code != http.StatusOK {
		t.Fatalf("send after rotation: %d %s", w.Code, w.Body)
	}
	if got := g.apns.last(t).Token; got != token(2) {
		t.Fatalf("send went to %s, want the rotated token", got)
	}
}

func TestSendRefusedWhileReplayCacheIsFull(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	handle := g.mint(g.enroll(token(1)), host)
	g.s.replays = newReplayCache(1)
	if w := g.send(host, handle); w.Code != http.StatusOK {
		t.Fatalf("send: %d", w.Code)
	}
	before := g.apns.count()
	g.advance(time.Millisecond)
	w := g.send(host, handle)
	expect(t, w, http.StatusTooManyRequests, "rate_limited")
	if w.Header().Get("Retry-After") == "" || g.apns.count() != before {
		t.Fatalf("full replay cache: Retry-After %q, reached APNs %v", w.Header().Get("Retry-After"), g.apns.count() != before)
	}
}

func TestSendValidation(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	handle := g.mint(g.enroll(token(1)), host)
	valid := map[string]any{"handle": handle, "payload": map[string]any{"v": 1}, "expiration": g.now.Add(time.Hour).Unix(), "priority": 5}
	cases := map[string]func(map[string]any){
		"array payload":  func(b map[string]any) { b["payload"] = []int{1} },
		"priority":       func(b map[string]any) { b["priority"] = 7 },
		"no expiration":  func(b map[string]any) { delete(b, "expiration") },
		"far expiration": func(b map[string]any) { b["expiration"] = g.now.Add(25 * time.Hour).Unix() },
		"collapse id":    func(b map[string]any) { b["collapseId"] = "has space" },
		"long collapse":  func(b map[string]any) { b["collapseId"] = strings.Repeat("a", 65) },
		"handle":         func(b map[string]any) { b["handle"] = "x" },
		"apns size":      func(b map[string]any) { b["payload"] = map[string]any{"c": strings.Repeat("a", 4000)} },
		"body size":      func(b map[string]any) { b["payload"] = map[string]any{"c": strings.Repeat("a", maxBodyBytes)} },
	}
	for name, mutate := range cases {
		body := map[string]any{}
		maps.Copy(body, valid)
		mutate(body)
		raw, _ := json.Marshal(body)
		w := g.serve(g.signed(host, http.MethodPost, "/v1/send", raw, g.now))
		if w.Code != http.StatusBadRequest || errorCode(w) != "invalid_request" {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	raw, _ := json.Marshal(valid)
	if w := g.serve(g.signed(host, http.MethodPost, "/v1/send", raw, g.now)); w.Code != http.StatusOK {
		t.Fatalf("valid send: %d %s", w.Code, w.Body)
	}
}

func TestHostSignature(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	handle := g.mint(g.enroll(token(1)), host)
	body := sendBody(handle, g.now)

	tampered := g.signed(host, http.MethodPost, "/v1/send", body, g.now)
	tampered.Body = io.NopCloser(bytes.NewReader(bytes.Replace(body, []byte(`"priority":10`), []byte(`"priority":5`), 1)))
	expect(t, g.serve(tampered), http.StatusUnauthorized, "unauthorized")

	wrongPath := g.signed(host, http.MethodPost, "/v1/other", body, g.now)
	wrongPath.URL.Path = "/v1/send"
	expect(t, g.serve(wrongPath), http.StatusUnauthorized, "unauthorized")

	swapped := g.signed(host, http.MethodPost, "/v1/send", body, g.now)
	swapped.Header.Set("supaterm-push-key", b64u.EncodeToString(hostKey(t).Public().(ed25519.PublicKey)))
	expect(t, g.serve(swapped), http.StatusUnauthorized, "unauthorized")

	missing := g.signed(host, http.MethodPost, "/v1/send", body, g.now)
	missing.Header.Del("supaterm-push-signature")
	expect(t, g.serve(missing), http.StatusUnauthorized, "unauthorized")

	expect(t, g.serve(g.signed(host, http.MethodPost, "/v1/send", body, g.now.Add(-signatureWindow-time.Millisecond))), http.StatusUnauthorized, "unauthorized")
	expect(t, g.serve(g.signed(host, http.MethodPost, "/v1/send", body, g.now.Add(signatureWindow+time.Millisecond))), http.StatusUnauthorized, "unauthorized")
	if w := g.serve(g.signed(host, http.MethodPost, "/v1/send", body, g.now.Add(signatureWindow))); w.Code != http.StatusOK {
		t.Fatalf("send at the window's edge: %d %s", w.Code, w.Body)
	}

	first := g.signed(host, http.MethodPost, "/v1/send", body, g.now)
	replay := first.Clone(first.Context())
	replay.Body = io.NopCloser(bytes.NewReader(body))
	if w := g.serve(first); w.Code != http.StatusOK {
		t.Fatalf("first send: %d %s", w.Code, w.Body)
	}
	before := g.apns.count()
	g.advance(signatureWindow - time.Second)
	expect(t, g.serve(replay), http.StatusUnauthorized, "unauthorized")
	if g.apns.count() != before {
		t.Fatal("a replay reached APNs")
	}
}

func TestHostDeletesOwnHandle(t *testing.T) {
	g := newGateway(t)
	owner, intruder := hostKey(t), hostKey(t)
	in := g.enroll(token(1))
	handle := g.mint(in, owner)
	path := "/v1/handles/" + handle

	expect(t, g.serve(g.signed(intruder, http.MethodDelete, path, nil, g.now)), http.StatusNotFound, "not_found")
	r := g.signed(owner, http.MethodDelete, path, nil, g.now)
	replay := r.Clone(r.Context())
	if w := g.serve(r); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	expect(t, g.serve(replay), http.StatusNotFound, "not_found")
	expect(t, g.send(owner, handle), http.StatusGone, "gone")
	if w := g.call(http.MethodGet, "/v1/installations/"+in.InstallationID, in.OwnerToken, nil); !strings.Contains(w.Body.String(), `"handles":0`) {
		t.Fatalf("installation after delete: %s", w.Body)
	}
}

func TestHealth(t *testing.T) {
	g := newGateway(t)
	w := g.serve(httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK || w.Body.String() != "ok" {
		t.Fatalf("healthz: %d %q", w.Code, w.Body)
	}
	g.store.Close()
	if w := g.serve(httptest.NewRequest(http.MethodGet, "/healthz", nil)); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz with a closed store: %d", w.Code)
	}
}
