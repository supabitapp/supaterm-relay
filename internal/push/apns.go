package push

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const providerTokenTTL = 50 * time.Minute

var apnsURLs = map[string]string{
	Sandbox:    "https://api.sandbox.push.apple.com",
	Production: "https://api.push.apple.com",
}

type apnsClient struct {
	http   *http.Client
	teamID string
	keys   map[string]APNsKey
	urls   map[string]string

	mu     sync.Mutex
	tokens map[string]providerToken
}

type providerToken struct {
	value  string
	issued time.Time
}

func newAPNsClient(cfg APNsConfig) *apnsClient {
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	client := &http.Client{
		Timeout: upstreamTimeout,
		Transport: &http.Transport{
			Protocols:           &protocols,
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: upstreamTimeout,
			IdleConnTimeout:     10 * time.Minute,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &apnsClient{http: client, teamID: cfg.TeamID, keys: cfg.Keys, urls: apnsURLs, tokens: map[string]providerToken{}}
}

func (c *apnsClient) deliver(ctx context.Context, g grant, n notification, now time.Time) result {
	body := apnsPayload(n)
	if len(body) > maxPlatformPayload {
		return result{outcome: tooLarge}
	}
	key, ok := c.keys[g.Environment]
	if !ok {
		return result{outcome: misconfigured, reason: "no key for " + g.Environment}
	}
	jwt, err := c.providerToken(g.Environment, key, now)
	if err != nil {
		return result{outcome: misconfigured, reason: "sign provider token"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.urls[g.Environment]+"/3/device/"+g.Token, bytes.NewReader(body))
	if err != nil {
		return result{outcome: unavailable, reason: "build request"}
	}
	priority := "5"
	if n.urgent {
		priority = "10"
	}
	expiration := int64(0)
	if n.ttl > 0 {
		expiration = now.Add(n.ttl).Unix()
	}
	req.Header.Set("authorization", "bearer "+jwt)
	req.Header.Set("content-type", "application/json")
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-topic", g.Topic)
	req.Header.Set("apns-priority", priority)
	req.Header.Set("apns-expiration", strconv.FormatInt(expiration, 10))
	resp, err := c.http.Do(req)
	if err != nil {
		return result{outcome: unavailable, reason: "transport"}
	}
	defer resp.Body.Close()
	var reply struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxUpstreamReply)).Decode(&reply)
	if resp.StatusCode == http.StatusForbidden && reply.Reason == "ExpiredProviderToken" {
		c.forget(g.Environment, jwt)
	}
	return result{outcome: classifyAPNs(resp.StatusCode, reply.Reason), status: resp.StatusCode, reason: reply.Reason}
}

func classifyAPNs(status int, reason string) outcome {
	switch {
	case status == http.StatusOK:
		return delivered
	case status == http.StatusGone,
		status == http.StatusBadRequest && (reason == "BadDeviceToken" || reason == "DeviceTokenNotForTopic"):
		return tokenGone
	case status == http.StatusRequestEntityTooLarge:
		return tooLarge
	case status == http.StatusForbidden,
		status == http.StatusBadRequest && (reason == "BadTopic" || reason == "TopicDisallowed" || reason == "MissingTopic"):
		return misconfigured
	default:
		return unavailable
	}
}

func apnsPayload(n notification) []byte {
	aps := map[string]any{
		"alert":           map[string]string{"title": n.title, "body": n.body},
		"mutable-content": 1,
	}
	if n.sound {
		aps["sound"] = "default"
	}
	payload := map[string]any{"aps": aps}
	for k, v := range n.data {
		payload[k] = v
	}
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return body
}

func (c *apnsClient) providerToken(env string, key APNsKey, now time.Time) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t := c.tokens[env]; t.value != "" && now.Sub(t.issued) < providerTokenTTL {
		return t.value, nil
	}
	value, err := signES256(key.Key, map[string]string{"alg": "ES256", "kid": key.ID}, map[string]any{"iss": c.teamID, "iat": now.Unix()})
	if err != nil {
		return "", err
	}
	c.tokens[env] = providerToken{value: value, issued: now}
	return value, nil
}

func (c *apnsClient) forget(env, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tokens[env].value == value {
		delete(c.tokens, env)
	}
}

func signES256(key *ecdsa.PrivateKey, header, claims any) (string, error) {
	encodedHeader, _ := json.Marshal(header)
	encodedClaims, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(encodedHeader) + "." + enc.EncodeToString(encodedClaims)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	var sig [64]byte
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + enc.EncodeToString(sig[:]), nil
}
