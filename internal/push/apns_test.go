package push

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSendMapsAPNsResults(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		reason  string
		want    int
		code    string
		retires bool
	}{
		{"accepted", 200, "", 200, "", false},
		{"unregistered", 410, "Unregistered", 410, "gone", true},
		{"expired token", 410, "ExpiredToken", 410, "gone", true},
		{"bad token", 400, "BadDeviceToken", 410, "gone", true},
		{"wrong topic", 400, "DeviceTokenNotForTopic", 410, "gone", true},
		{"throttled", 429, "TooManyRequests", 502, "apns_unavailable", false},
		{"apns error", 500, "InternalServerError", 502, "apns_unavailable", false},
		{"apns down", 503, "ServiceUnavailable", 502, "apns_unavailable", false},
		{"bad credential", 403, "InvalidProviderToken", 503, "gateway_unavailable", false},
		{"topic disallowed", 400, "TopicDisallowed", 503, "gateway_unavailable", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newGateway(t)
			host := hostKey(t)
			in := g.enroll(token(1))
			handle := g.mint(in, host)
			g.apns.reply(token(1), c.status, c.reason)
			w := g.send(host, handle)
			if w.Code != c.want || errorCode(w) != c.code {
				t.Fatalf("got %d %s, want %d %q", w.Code, w.Body, c.want, c.code)
			}
			_, err := g.store.Installation(t.Context(), in.InstallationID)
			if retired := err == ErrNotFound; retired != c.retires {
				t.Fatalf("installation retired = %v, want %v", retired, c.retires)
			}
			if c.retires {
				expect(t, g.send(host, handle), http.StatusGone, "gone")
			}
		})
	}
}

func TestSendReportsNetworkFailureAsRetryable(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	handle := g.mint(g.enroll(token(1)), host)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	for _, p := range g.s.apns.providers {
		p.cred.URL = "https://" + ln.Addr().String()
	}
	expect(t, g.send(host, handle), http.StatusBadGateway, "apns_unavailable")
}

func TestProviderTokenIsCachedPerEnvironment(t *testing.T) {
	g := newGateway(t)
	host := hostKey(t)
	handle := g.mint(g.enroll(token(1)), host)
	auth := func() string {
		t.Helper()
		if w := g.send(host, handle); w.Code != http.StatusOK {
			t.Fatalf("send: %d %s", w.Code, w.Body)
		}
		return g.apns.last(t).Header.Get("Authorization")
	}
	first := auth()
	claims := verifyProviderToken(t, strings.TrimPrefix(first, "bearer "), &g.key.PublicKey)
	if claims.Kid != "SANDBOXKEY" || claims.Iss != "TEAM123456" || claims.Iat != g.now.Unix() {
		t.Fatalf("provider token claims = %+v", claims)
	}
	g.advance(49 * time.Minute)
	if auth() != first {
		t.Fatal("provider token was not reused within 50 minutes")
	}
	g.advance(2 * time.Minute)
	refreshed := auth()
	if refreshed == first {
		t.Fatal("provider token was not refreshed after 50 minutes")
	}

	g.apns.reply(token(1), http.StatusForbidden, "ExpiredProviderToken")
	g.advance(time.Second)
	expect(t, g.send(host, handle), http.StatusServiceUnavailable, "gateway_unavailable")
	g.apns.reply(token(1), http.StatusOK, "")
	g.advance(time.Second)
	if auth() == refreshed {
		t.Fatal("an expired provider token was reused")
	}

	if w := g.call(http.MethodPost, "/v1/enrollments", "", map[string]string{"token": token(2), "topic": testTopic, "environment": Production}); w.Code != http.StatusCreated {
		t.Fatalf("production enrollment: %d %s", w.Code, w.Body)
	}
	if kid := verifyProviderToken(t, strings.TrimPrefix(g.apns.last(t).Header.Get("Authorization"), "bearer "), &g.key.PublicKey).Kid; kid != "PRODKEY" {
		t.Fatalf("production push signed with %q", kid)
	}
}

type providerClaims struct {
	Kid string
	Iss string
	Iat int64
}

func verifyProviderToken(t *testing.T, jwt string, pub *ecdsa.PublicKey) providerClaims {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("provider token %q is not a JWT", jwt)
	}
	var header struct{ Alg, Kid string }
	var claims struct {
		Iss string
		Iat int64
	}
	for i, v := range []any{&header, &claims} {
		raw, err := b64u.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, v); err != nil {
			t.Fatal(err)
		}
	}
	sig, err := b64u.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature: %v, %d bytes", err, len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if header.Alg != "ES256" || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatalf("provider token does not verify as ES256")
	}
	return providerClaims{Kid: header.Kid, Iss: claims.Iss, Iat: claims.Iat}
}
