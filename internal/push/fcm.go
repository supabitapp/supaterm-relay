package push

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	fcmScope          = "https://www.googleapis.com/auth/firebase.messaging"
	accessTokenMargin = 5 * time.Minute
)

type fcmClient struct {
	http    *http.Client
	cred    FCMCredential
	sendURL string

	mu      sync.Mutex
	access  string
	expires time.Time
}

func newFCMClient(cred FCMCredential) *fcmClient {
	return &fcmClient{
		http:    &http.Client{Timeout: upstreamTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		cred:    cred,
		sendURL: "https://fcm.googleapis.com/v1/projects/" + url.PathEscape(cred.ProjectID) + "/messages:send",
	}
}

func (c *fcmClient) deliver(ctx context.Context, g grant, n notification, now time.Time) result {
	data, err := json.Marshal(n.data)
	if err != nil {
		panic(err)
	}
	if len(data) > maxPlatformPayload {
		return result{outcome: tooLarge}
	}
	priority := "NORMAL"
	if n.urgent {
		priority = "HIGH"
	}
	body, err := json.Marshal(map[string]any{"message": map[string]any{
		"token":   g.Token,
		"data":    json.RawMessage(data),
		"android": map[string]string{"priority": priority, "ttl": fmt.Sprintf("%ds", int64(n.ttl/time.Second))},
	}})
	if err != nil {
		panic(err)
	}
	access, failure := c.accessToken(ctx, now)
	if failure != nil {
		return *failure
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.sendURL, bytes.NewReader(body))
	if err != nil {
		return result{outcome: unavailable, reason: "build request"}
	}
	req.Header.Set("authorization", "Bearer "+access)
	req.Header.Set("content-type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return result{outcome: unavailable, reason: "transport"}
	}
	defer resp.Body.Close()
	var reply struct {
		Error struct {
			Status  string `json:"status"`
			Details []struct {
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxUpstreamReply)).Decode(&reply)
	reason := reply.Error.Status
	for _, d := range reply.Error.Details {
		if d.ErrorCode != "" {
			reason = d.ErrorCode
		}
	}
	if resp.StatusCode == http.StatusUnauthorized {
		c.forget(access)
	}
	return result{outcome: classifyFCM(resp.StatusCode, reason), status: resp.StatusCode, reason: reason}
}

func classifyFCM(status int, reason string) outcome {
	switch {
	case status == http.StatusOK:
		return delivered
	case reason == "UNREGISTERED", reason == "SENDER_ID_MISMATCH":
		return tokenGone
	case status == http.StatusUnauthorized, status == http.StatusForbidden, status == http.StatusNotFound:
		return misconfigured
	default:
		return unavailable
	}
}

func (c *fcmClient) accessToken(ctx context.Context, now time.Time) (string, *result) {
	c.mu.Lock()
	access, expires := c.access, c.expires
	c.mu.Unlock()
	if access != "" && now.Before(expires) {
		return access, nil
	}
	assertion, err := signRS256(c.cred.Key, map[string]any{
		"iss":   c.cred.ClientEmail,
		"scope": fcmScope,
		"aud":   c.cred.TokenURL,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	if err != nil {
		return "", &result{outcome: misconfigured, reason: "sign access token request"}
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cred.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", &result{outcome: misconfigured, reason: "build access token request"}
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", &result{outcome: unavailable, reason: "access token transport"}
	}
	defer resp.Body.Close()
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxUpstreamReply)).Decode(&token)
	switch {
	case resp.StatusCode >= 500:
		return "", &result{outcome: unavailable, status: resp.StatusCode, reason: "access token"}
	case resp.StatusCode != http.StatusOK || token.AccessToken == "":
		return "", &result{outcome: misconfigured, status: resp.StatusCode, reason: "access token"}
	}
	c.mu.Lock()
	c.access = token.AccessToken
	c.expires = now.Add(time.Duration(token.ExpiresIn)*time.Second - accessTokenMargin)
	c.mu.Unlock()
	return token.AccessToken, nil
}

func (c *fcmClient) forget(access string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.access == access {
		c.access = ""
	}
}

func signRS256(key *rsa.PrivateKey, claims any) (string, error) {
	encodedClaims, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	input := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc.EncodeToString(encodedClaims)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + enc.EncodeToString(sig), nil
}
