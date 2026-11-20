package push

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const apnsToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const fcmToken = "dGVzdC10b2tlbg:APA91bFakeRegistrationTokenForTests_-"

func TestSubscribeDeliversTheEndpointOnlyThroughThePlatform(t *testing.T) {
	for _, p := range []func(*testing.T) phone{
		func(t *testing.T) phone { return apnsPhone(t, apnsToken) },
		func(t *testing.T) phone { return fcmPhone(t, fcmToken) },
	} {
		e := newTestEnv(t)
		phone := p(t)
		w := e.subscribeRequest(phone, newKey(t))
		if w.Code != http.StatusAccepted || strings.Contains(w.Body.String(), "/v1/push/") {
			t.Fatalf("%s subscribe answered %d %s", phone.platform, w.Code, w.Body)
		}
		sub := e.delivered(phone).subscription(t)
		if !strings.HasPrefix(sub.Endpoint, testOrigin+"/v1/push/") || strings.Contains(sub.Endpoint, phone.token) {
			t.Fatalf("endpoint %q", sub.Endpoint)
		}
		if sub.ExpiresAt != e.now().Add(grantLifetime).Unix() || sub.RenewAfter != e.now().Add(grantLifetime/2).Unix() {
			t.Fatalf("lifetime %+v", sub)
		}
	}
}

func TestSubscribeAPNsAlertAndProviderToken(t *testing.T) {
	e := newTestEnv(t)
	e.subscribe(apnsPhone(t, apnsToken), newKey(t))
	r := e.apns.last(t, "/3/device/")
	var payload struct {
		APS struct {
			Alert          map[string]string `json:"alert"`
			MutableContent int               `json:"mutable-content"`
			Sound          string            `json:"sound"`
		} `json:"aps"`
	}
	_ = json.Unmarshal(r.body, &payload)
	if payload.APS.Alert["body"] != "Notifications are on" || payload.APS.MutableContent != 1 || payload.APS.Sound != "" {
		t.Fatalf("subscription alert %+v", payload.APS)
	}
	if r.header.Get("apns-topic") != testTopic || r.header.Get("apns-push-type") != "alert" || r.header.Get("apns-priority") != "10" {
		t.Fatalf("headers %v", r.header)
	}
	jwt := strings.TrimPrefix(r.header.Get("authorization"), "bearer ")
	pubKey, _ := e.apnsKey.PublicKey.Bytes()
	claims, ok := verifyES256(pubKey, jwt)
	if !ok || !strings.Contains(string(claims), `"iss":"TEAM123456"`) {
		t.Fatalf("provider token %q", jwt)
	}
}

func TestSubscribeRejectsBadTargets(t *testing.T) {
	e := newTestEnv(t)
	host := newKey(t)
	cases := []struct {
		name   string
		phone  phone
		status int
		code   string
	}{
		{"unknown platform", phone{platform: "webpush", token: apnsToken, management: newKey(t)}, 400, "invalid_request"},
		{"topic not allowed", phone{platform: "apns", token: apnsToken, environment: Sandbox, topic: "com.example.other", management: newKey(t)}, 403, "topic_not_allowed"},
		{"environment without key", phone{platform: "apns", token: apnsToken, environment: Production, topic: testTopic, management: newKey(t)}, 400, "platform_not_configured"},
		{"unknown environment", phone{platform: "apns", token: apnsToken, environment: "staging", topic: testTopic, management: newKey(t)}, 400, "invalid_request"},
		{"apns token not hex", apnsPhone(t, strings.Repeat("zz", 32)), 400, "invalid_request"},
		{"fcm token with a topic", phone{platform: "fcm", token: fcmToken, topic: testTopic, management: newKey(t)}, 400, "invalid_request"},
		{"fcm token with a slash", fcmPhone(t, "abc/def/ghi/jkl/mno"), 400, "invalid_request"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expect(t, e.subscribeRequest(c.phone, host), c.status, c.code)
		})
	}
	expect(t, e.post("/v1/subscriptions", `{"platform":"apns","token":"`+apnsToken+`","topic":"`+testTopic+`","environment":"sandbox","hostKey":"AAAA","managementKey":"`+pub(host)+`","request":"r"}`, nil), 400, "invalid_request")
	expect(t, e.post("/v1/subscriptions", `{"platform":"apns","token":"`+apnsToken+`","topic":"`+testTopic+`","environment":"sandbox","hostKey":"`+pub(host)+`","managementKey":"`+pub(host)+`"}`, nil), 400, "invalid_request")
	if n := e.apns.count("/"); n != 0 {
		t.Fatalf("rejected subscriptions reached APNs %d times", n)
	}
}

func TestPushForwardsCiphertextUnderAFixedAlert(t *testing.T) {
	e := newTestEnv(t)
	host := newKey(t)
	ciphertext := "\x00\x01opaque aes128gcm record"
	sub := e.subscribe(apnsPhone(t, apnsToken), host)
	w := e.send(sub.Endpoint, host, http.Header{"Supaterm-Alert": {"needs-input"}, "Ttl": {"600"}}, ciphertext)
	if w.Code != http.StatusCreated {
		t.Fatalf("send: %d %s", w.Code, w.Body)
	}
	r := e.apns.last(t, "/3/device/"+apnsToken)
	var payload map[string]any
	_ = json.Unmarshal(r.body, &payload)
	aps := payload["aps"].(map[string]any)
	if aps["alert"].(map[string]any)["body"] != "An agent needs your input" || aps["mutable-content"] != 1.0 || aps["sound"] != "default" {
		t.Fatalf("aps %v", aps)
	}
	if payload["c"] != base64.RawURLEncoding.EncodeToString([]byte(ciphertext)) || payload["type"] != "message" || payload["alert"] != "needs-input" {
		t.Fatalf("payload %v", payload)
	}
	if r.header.Get("apns-priority") != "10" || r.header.Get("apns-expiration") != itoa64(e.now().Unix()+600) || r.header.Get("apns-collapse-id") != "" || r.header.Get("apns-topic") != testTopic {
		t.Fatalf("headers %v", r.header)
	}

	e.send(sub.Endpoint, host, http.Header{"Urgency": {"normal"}, "Ttl": {"0"}}, ciphertext)
	if r := e.apns.last(t, "/3/device/"); r.header.Get("apns-priority") != "5" || r.header.Get("apns-expiration") != "0" {
		t.Fatalf("normal urgency headers %v", r.header)
	}

	for alert := range alertText {
		if w := e.send(sub.Endpoint, host, http.Header{"Supaterm-Alert": {alert}}, strings.Repeat("x", 2954)); w.Code != http.StatusCreated {
			t.Fatalf("documented 2,954-byte body with %s: %d %s", alert, w.Code, w.Body)
		}
	}
}

func TestPushThroughFCM(t *testing.T) {
	e := newTestEnv(t)
	host := newKey(t)
	phone := fcmPhone(t, fcmToken)
	sub := e.subscribe(phone, host)
	if w := e.send(sub.Endpoint, host, nil, "ciphertext"); w.Code != http.StatusCreated {
		t.Fatalf("send: %d %s", w.Code, w.Body)
	}
	r := e.fcm.last(t, "/send")
	var msg struct {
		Message struct {
			Data    map[string]string `json:"data"`
			Android map[string]string `json:"android"`
		} `json:"message"`
	}
	_ = json.Unmarshal(r.body, &msg)
	if msg.Message.Data["c"] != base64.RawURLEncoding.EncodeToString([]byte("ciphertext")) || msg.Message.Data["alert"] != "activity" || msg.Message.Android["priority"] != "HIGH" || msg.Message.Android["ttl"] != "60s" {
		t.Fatalf("fcm message %+v", msg.Message)
	}
	if r.header.Get("authorization") != "Bearer fcm-access" {
		t.Fatalf("authorization %q", r.header.Get("authorization"))
	}
	if n := e.fcm.count("/token"); n != 1 {
		t.Fatalf("access token fetched %d times for two sends", n)
	}
	assertion := form(t, e.fcm.last(t, "/token").body)
	claims := verifyRS256(t, &fcmKey().PublicKey, assertion.Get("assertion"))
	if assertion.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || claims["scope"] != fcmScope || claims["iss"] != e.cfg.FCM.ClientEmail {
		t.Fatalf("token request %v %v", assertion, claims)
	}
}

func TestPushRequiresTheGrantsHostAndAValidRequest(t *testing.T) {
	e := newTestEnv(t)
	host, other := newKey(t), newKey(t)
	sub := e.subscribe(apnsPhone(t, apnsToken), host)
	sealed := strings.TrimPrefix(sub.Endpoint, testOrigin+pushPath)
	tampered := testOrigin + pushPath + sealed[:len(sealed)-2] + flip(sealed[len(sealed)-2:])
	cases := []struct {
		name     string
		endpoint string
		header   http.Header
		body     string
		status   int
		code     string
	}{
		{"tampered endpoint", tampered, nil, "c", 404, "endpoint_invalid"},
		{"no authorization", sub.Endpoint, http.Header{"Authorization": nil}, "c", 401, "unauthorized"},
		{"another host's key", sub.Endpoint, http.Header{"Authorization": {vapid(t, other, testOrigin, e.now().Add(time.Hour))}}, "c", 401, "unauthorized"},
		{"key swapped under a valid token", sub.Endpoint, http.Header{"Authorization": {strings.Replace(vapid(t, other, testOrigin, e.now().Add(time.Hour)), pub(other), pub(host), 1)}}, "c", 401, "unauthorized"},
		{"wrong audience", sub.Endpoint, http.Header{"Authorization": {vapid(t, host, "https://other.example", e.now().Add(time.Hour))}}, "c", 401, "unauthorized"},
		{"token valid too long", sub.Endpoint, http.Header{"Authorization": {vapid(t, host, testOrigin, e.now().Add(2*time.Hour))}}, "c", 401, "unauthorized"},
		{"expired token", sub.Endpoint, http.Header{"Authorization": {vapid(t, host, testOrigin, e.now())}}, "c", 401, "unauthorized"},
		{"missing TTL", sub.Endpoint, http.Header{"Ttl": nil}, "c", 400, "invalid_request"},
		{"TTL over four weeks", sub.Endpoint, http.Header{"Ttl": {"2419201"}}, "c", 400, "invalid_request"},
		{"TTL that overflows a duration", sub.Endpoint, http.Header{"Ttl": {"9223372036854775807"}}, "c", 400, "invalid_request"},
		{"unknown urgency", sub.Endpoint, http.Header{"Urgency": {"urgent"}}, "c", 400, "invalid_request"},
		{"unknown alert", sub.Endpoint, http.Header{"Supaterm-Alert": {"custom text"}}, "c", 400, "invalid_request"},
		{"not aes128gcm", sub.Endpoint, http.Header{"Content-Encoding": {"aesgcm"}}, "c", 415, "unsupported_encoding"},
		{"empty body", sub.Endpoint, nil, "", 400, "invalid_request"},
		{"body over 4 KiB", sub.Endpoint, nil, strings.Repeat("x", maxPushBody+1), 413, "payload_too_large"},
		{"APNs payload over 4 KiB", sub.Endpoint, nil, strings.Repeat("x", 3000), 413, "payload_too_large"},
	}
	before := e.apns.count("/")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expect(t, e.send(c.endpoint, host, c.header, c.body), c.status, c.code)
		})
	}
	if n := e.apns.count("/") - before; n != 0 {
		t.Fatalf("rejected sends reached APNs %d times", n)
	}
}

func TestUpstreamAnswersMapToHostErrors(t *testing.T) {
	cases := []struct {
		platform string
		status   int
		body     string
		want     int
		code     string
	}{
		{"apns", 410, `{"reason":"Unregistered"}`, 410, "token_unregistered"},
		{"apns", 400, `{"reason":"BadDeviceToken"}`, 410, "token_unregistered"},
		{"apns", 400, `{"reason":"DeviceTokenNotForTopic"}`, 410, "token_unregistered"},
		{"apns", 413, `{"reason":"PayloadTooLarge"}`, 413, "payload_too_large"},
		{"apns", 429, `{"reason":"TooManyRequests"}`, 502, "upstream_unavailable"},
		{"apns", 503, `{"reason":"ServiceUnavailable"}`, 502, "upstream_unavailable"},
		{"apns", 403, `{"reason":"InvalidProviderToken"}`, 503, "gateway_misconfigured"},
		{"apns", 400, `{"reason":"TopicDisallowed"}`, 503, "gateway_misconfigured"},
		{"fcm", 404, `{"error":{"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}`, 410, "token_unregistered"},
		{"fcm", 403, `{"error":{"status":"PERMISSION_DENIED","details":[{"errorCode":"SENDER_ID_MISMATCH"}]}}`, 410, "token_unregistered"},
		{"fcm", 400, `{"error":{"status":"INVALID_ARGUMENT","details":[{"errorCode":"INVALID_ARGUMENT"}]}}`, 502, "upstream_unavailable"},
		{"fcm", 429, `{"error":{"status":"RESOURCE_EXHAUSTED","details":[{"errorCode":"QUOTA_EXCEEDED"}]}}`, 502, "upstream_unavailable"},
		{"fcm", 401, `{"error":{"status":"UNAUTHENTICATED"}}`, 503, "gateway_misconfigured"},
		{"fcm", 404, `{"error":{"status":"NOT_FOUND"}}`, 503, "gateway_misconfigured"},
	}
	for _, c := range cases {
		t.Run(c.platform+" "+c.body, func(t *testing.T) {
			e := newTestEnv(t)
			host := newKey(t)
			p, upstream, token := apnsPhone(t, apnsToken), e.apns, apnsToken
			if c.platform == "fcm" {
				p, upstream, token = fcmPhone(t, fcmToken), e.fcm, fcmToken
			}
			sub := e.subscribe(p, host)
			upstream.reply(token, c.status, c.body)
			w := e.send(sub.Endpoint, host, nil, "c")
			expect(t, w, c.want, c.code)
			if retry := w.Header().Get("Retry-After"); (c.want >= 500) != (retry != "") {
				t.Fatalf("Retry-After %q on %d", retry, c.want)
			}
		})
	}
}

func TestFCMRefetchesTheAccessTokenAfterUnauthorized(t *testing.T) {
	e := newTestEnv(t)
	host := newKey(t)
	sub := e.subscribe(fcmPhone(t, fcmToken), host)
	e.fcm.reply(fcmToken, 401, `{"error":{"status":"UNAUTHENTICATED"}}`)
	e.send(sub.Endpoint, host, nil, "c")
	e.fcm.reply(fcmToken, 200, `{}`)
	if w := e.send(sub.Endpoint, host, nil, "c"); w.Code != http.StatusCreated {
		t.Fatalf("send after refresh: %d %s", w.Code, w.Body)
	}
	if n := e.fcm.count("/token"); n != 2 {
		t.Fatalf("access token fetched %d times, want 2", n)
	}
	e.advance(56 * time.Minute)
	e.send(sub.Endpoint, host, nil, "c")
	if n := e.fcm.count("/token"); n != 3 {
		t.Fatalf("access token not refreshed before expiry: %d fetches", n)
	}
}

func TestExpiredAndRevokedEndpoints(t *testing.T) {
	e := newTestEnv(t)
	host := newKey(t)
	p := apnsPhone(t, apnsToken)
	sub := e.subscribe(p, host)
	e.advance(grantLifetime)
	expect(t, e.send(sub.Endpoint, host, nil, "c"), 403, "endpoint_expired")
	if w := e.phoneRequest(p, "revoke", sub.Endpoint, nil); w.Code != http.StatusNoContent {
		t.Fatalf("revoke expired endpoint: %d %s", w.Code, w.Body)
	}
	expect(t, e.send(sub.Endpoint, host, nil, "c"), 410, "endpoint_revoked")
}

func TestRevocationSurvivesRestartAndCoversRenewedEndpoints(t *testing.T) {
	e := newTestEnv(t)
	host := newKey(t)
	p := apnsPhone(t, apnsToken)
	first := e.subscribe(p, host)
	e.advance(grantLifetime / 2)
	w := e.phoneRequest(p, "renew", first.Endpoint, nil)
	var renewed subscription
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &renewed) != nil || renewed.Endpoint == first.Endpoint {
		t.Fatalf("renew: %d %s", w.Code, w.Body)
	}
	if w := e.phoneRequest(p, "revoke", renewed.Endpoint, nil); w.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	e.start()
	for _, endpoint := range []string{first.Endpoint, renewed.Endpoint} {
		expect(t, e.send(endpoint, host, nil, "c"), 410, "endpoint_revoked")
	}
	expect(t, e.phoneRequest(p, "renew", renewed.Endpoint, nil), 410, "endpoint_revoked")
	e.advance(grantLifetime)
	expect(t, e.send(renewed.Endpoint, host, nil, "c"), 403, "endpoint_expired")
	if n := e.s.revoked.size(); n != 1 {
		t.Fatalf("tombstones before restart = %d", n)
	}
	e.start()
	if n := e.s.revoked.size(); n != 0 {
		t.Fatalf("expired tombstone kept after restart: %d", n)
	}
}

func TestRenew(t *testing.T) {
	e := newTestEnv(t)
	host := newKey(t)
	p := apnsPhone(t, apnsToken)
	sub := e.subscribe(p, host)
	expect(t, e.phoneRequest(p, "renew", sub.Endpoint, nil), 409, "renewal_too_early")
	expect(t, e.phoneRequest(p, "renew", sub.Endpoint, map[string]any{"token": strings.ToUpper(apnsToken), "request": "req-1"}), 409, "renewal_too_early")

	e.advance(grantLifetime/2 + time.Hour)
	stranger := phone{management: newKey(t)}
	cases := []struct {
		name  string
		phone phone
		extra map[string]any
	}{
		{"another key", stranger, nil},
		{"revoke request replayed", p, map[string]any{"act": "revoke"}},
		{"wrong audience", p, map[string]any{"aud": "https://other.example"}},
		{"expired request", p, map[string]any{"iat": e.now().Add(-10 * time.Minute).Unix(), "exp": e.now().Add(-5 * time.Minute).Unix()}},
		{"request valid too long", p, map[string]any{"exp": e.now().Add(time.Hour).Unix()}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expect(t, e.phoneRequest(c.phone, "renew", sub.Endpoint, c.extra), 401, "unauthorized")
		})
	}
	expect(t, e.phoneRequest(p, "renew", testOrigin+pushPath+"AAAA", nil), 404, "endpoint_invalid")

	w := e.phoneRequest(p, "renew", sub.Endpoint, nil)
	var renewed subscription
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &renewed) != nil {
		t.Fatalf("renew: %d %s", w.Code, w.Body)
	}
	if renewed.ExpiresAt != e.now().Add(grantLifetime).Unix() || renewed.Endpoint == sub.Endpoint {
		t.Fatalf("renewed %+v from %+v", renewed, sub)
	}
	for _, endpoint := range []string{sub.Endpoint, renewed.Endpoint} {
		if w := e.send(endpoint, host, nil, "c"); w.Code != http.StatusCreated {
			t.Fatalf("send after renewal: %d %s", w.Code, w.Body)
		}
	}
	e.advance(grantLifetime / 2)
	expect(t, e.phoneRequest(p, "renew", sub.Endpoint, nil), 403, "endpoint_expired")
}

func TestRenewToANewTokenRepeatsThePossessionProof(t *testing.T) {
	e := newTestEnv(t)
	host := newKey(t)
	p := apnsPhone(t, apnsToken)
	sub := e.subscribe(p, host)
	moved := p
	moved.token = strings.Repeat("ab", 32)
	expect(t, e.phoneRequest(p, "renew", sub.Endpoint, map[string]any{"token": moved.token}), 400, "invalid_request")
	w := e.phoneRequest(p, "renew", sub.Endpoint, map[string]any{"token": moved.token, "request": "req-1"})
	if w.Code != http.StatusAccepted || strings.Contains(w.Body.String(), "/v1/push/") {
		t.Fatalf("retarget answered %d %s", w.Code, w.Body)
	}
	retargeted := e.delivered(moved).subscription(t)
	if w := e.send(retargeted.Endpoint, host, nil, "c"); w.Code != http.StatusCreated {
		t.Fatalf("send to the new token: %d %s", w.Code, w.Body)
	}
	if e.apns.last(t, "/3/device/").path != "/3/device/"+moved.token {
		t.Fatal("message did not reach the new token")
	}
}

func TestRenewalNeverOutlivesAConcurrentRevocation(t *testing.T) {
	e := newTestEnv(t)
	host := newKey(t)
	p := apnsPhone(t, apnsToken)
	sub := e.subscribe(p, host)
	e.advance(grantLifetime / 2)
	ticking := e.s.now
	e.s.now = func() time.Time {
		e.advance(time.Second)
		return ticking()
	}
	renewals := make(chan subscription, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			w := e.phoneRequest(p, "renew", sub.Endpoint, map[string]any{"exp": e.now().Add(5 * time.Minute).Unix()})
			var renewed subscription
			if w.Code == http.StatusOK && json.Unmarshal(w.Body.Bytes(), &renewed) == nil {
				renewals <- renewed
			}
		})
	}
	wg.Go(func() {
		if w := e.phoneRequest(p, "revoke", sub.Endpoint, map[string]any{"exp": e.now().Add(5 * time.Minute).Unix()}); w.Code != http.StatusNoContent {
			t.Errorf("revoke: %d %s", w.Code, w.Body)
		}
	})
	wg.Wait()
	close(renewals)
	e.s.now = ticking
	latest := sub
	for renewed := range renewals {
		if renewed.ExpiresAt > latest.ExpiresAt {
			latest = renewed
		}
	}
	e.advance(time.Duration(latest.ExpiresAt-e.now().Unix()-1) * time.Second)
	expect(t, e.send(latest.Endpoint, host, nil, "c"), 410, "endpoint_revoked")
}

func TestRemovedTopicStopsSendsAndRenewals(t *testing.T) {
	e := newTestEnv(t)
	host := newKey(t)
	p := apnsPhone(t, apnsToken)
	sub := e.subscribe(p, host)
	e.cfg.APNs.Topics = []string{"com.supaterm.mobile.dev"}
	e.start()
	expect(t, e.send(sub.Endpoint, host, nil, "c"), 503, "gateway_misconfigured")
	e.advance(grantLifetime / 2)
	expect(t, e.phoneRequest(p, "renew", sub.Endpoint, nil), 403, "topic_not_allowed")
}

func TestRateLimits(t *testing.T) {
	e := newTestEnv(t)
	host := newKey(t)
	sub := e.subscribe(apnsPhone(t, apnsToken), host)
	for range 10 {
		e.send(sub.Endpoint, host, nil, "c")
	}
	w := e.send(sub.Endpoint, host, nil, "c")
	expect(t, w, 429, "rate_limited")
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	other := e.subscribe(apnsPhone(t, strings.Repeat("cd", 32)), host)
	if w := e.send(other.Endpoint, host, nil, "c"); w.Code != http.StatusCreated {
		t.Fatalf("another grant was limited: %d %s", w.Code, w.Body)
	}

	device := apnsPhone(t, strings.Repeat("ef", 32))
	for range 10 {
		e.subscribe(device, newKey(t))
	}
	expect(t, e.subscribeRequest(device, newKey(t)), 429, "rate_limited")

	limited := 0
	for range 25 {
		r := httptest.NewRequest(http.MethodPost, "/v1/subscriptions", strings.NewReader("{}"))
		r.RemoteAddr = "198.51.100.7:1"
		w := httptest.NewRecorder()
		e.s.http.Handler.ServeHTTP(w, r)
		if w.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited != 5 {
		t.Fatalf("%d of 25 enrollments from one network were limited, want 5", limited)
	}
}

func TestDashboardReportsPushCounters(t *testing.T) {
	e := newTestEnv(t)
	host := newKey(t)
	sub := e.subscribe(apnsPhone(t, apnsToken), host)
	e.send(sub.Endpoint, host, nil, "ciphertext")
	e.send(sub.Endpoint, newKey(t), nil, "c")
	stats := e.s.dashboardStats()
	if stats.Counts[0].Value != 1 || stats.ForwardedMessages != 1 || stats.ForwardedBytes != int64(len("ciphertext")) || stats.RejectedByReason["unauthorized"] != 1 {
		t.Fatalf("stats %+v", stats)
	}
	w := e.serve(httptest.NewRequest(http.MethodGet, "/dashboard/", nil))
	body := w.Body.String()
	for _, want := range []string{"<title>Supaterm push</title>", "<h2>Push</h2>", "Subscriptions issued", "Revoked grants", "Unauthorized", "Push process"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard is missing %q:\n%s", want, body)
		}
	}
	if w := e.serve(httptest.NewRequest(http.MethodGet, "/healthz", nil)); w.Code != http.StatusOK {
		t.Fatalf("healthz %d", w.Code)
	}
}

func flip(s string) string {
	if s[0] == 'A' {
		return "B" + s[1:]
	}
	return "A" + s[1:]
}

func itoa64(n int64) string {
	return strconv.FormatInt(n, 10)
}
