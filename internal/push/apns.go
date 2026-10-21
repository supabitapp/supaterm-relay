package push

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	apnsTimeout        = 10 * time.Second
	providerTokenTTL   = 50 * time.Minute
	maxAPNsPayload     = 4096
	maxAPNsReasonBytes = 4096
)

type apnsOutcome int

const (
	apnsAccepted apnsOutcome = iota
	apnsGone
	apnsUnavailable
	apnsCredential
)

type apnsRequest struct {
	Environment string
	Token       string
	Topic       string
	Priority    int
	Expiration  int64
	CollapseID  string
	Body        []byte
}

type apnsResult struct {
	Outcome apnsOutcome
	Status  int
	Reason  string
}

type apnsClient struct {
	http   *http.Client
	teamID string
	now    func() time.Time

	mu        sync.Mutex
	providers map[string]*providerToken
}

type providerToken struct {
	cred   Credential
	value  string
	issued time.Time
}

func NewAPNsHTTPClient() *http.Client {
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	return &http.Client{
		Timeout: apnsTimeout,
		Transport: &http.Transport{
			Protocols:           &protocols,
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: apnsTimeout,
			IdleConnTimeout:     10 * time.Minute,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func newAPNsClient(client *http.Client, teamID string, creds map[string]Credential, now func() time.Time) *apnsClient {
	providers := map[string]*providerToken{}
	for env, cred := range creds {
		providers[env] = &providerToken{cred: cred}
	}
	return &apnsClient{http: client, teamID: teamID, now: now, providers: providers}
}

func (c *apnsClient) supports(env string) bool {
	_, ok := c.providers[env]
	return ok
}

func (c *apnsClient) send(ctx context.Context, req apnsRequest) apnsResult {
	p, ok := c.providers[req.Environment]
	if !ok {
		return apnsResult{Outcome: apnsCredential, Reason: "no key for environment"}
	}
	jwt, err := c.providerToken(p)
	if err != nil {
		return apnsResult{Outcome: apnsCredential, Reason: "sign provider token"}
	}
	ctx, cancel := context.WithTimeout(ctx, apnsTimeout)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cred.URL+"/3/device/"+req.Token, bytes.NewReader(req.Body))
	if err != nil {
		return apnsResult{Outcome: apnsUnavailable, Reason: "build request"}
	}
	hr.Header.Set("authorization", "bearer "+jwt)
	hr.Header.Set("content-type", "application/json")
	hr.Header.Set("apns-push-type", "alert")
	hr.Header.Set("apns-topic", req.Topic)
	hr.Header.Set("apns-priority", strconv.Itoa(req.Priority))
	hr.Header.Set("apns-expiration", strconv.FormatInt(req.Expiration, 10))
	if req.CollapseID != "" {
		hr.Header.Set("apns-collapse-id", req.CollapseID)
	}
	resp, err := c.http.Do(hr)
	if err != nil {
		return apnsResult{Outcome: apnsUnavailable, Reason: "transport"}
	}
	defer resp.Body.Close()
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxAPNsReasonBytes)).Decode(&body)
	if resp.StatusCode == http.StatusForbidden && body.Reason == "ExpiredProviderToken" {
		c.expire(p, jwt)
	}
	return apnsResult{Outcome: classify(resp.StatusCode, body.Reason), Status: resp.StatusCode, Reason: body.Reason}
}

func classify(status int, reason string) apnsOutcome {
	switch {
	case status == http.StatusOK:
		return apnsAccepted
	case status == http.StatusGone,
		status == http.StatusBadRequest && (reason == "BadDeviceToken" || reason == "DeviceTokenNotForTopic"):
		return apnsGone
	case status == http.StatusForbidden,
		status == http.StatusBadRequest && (reason == "BadTopic" || reason == "TopicDisallowed" || reason == "MissingTopic"):
		return apnsCredential
	default:
		return apnsUnavailable
	}
}

func (c *apnsClient) providerToken(p *providerToken) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if p.value != "" && now.Sub(p.issued) < providerTokenTTL {
		return p.value, nil
	}
	value, err := signProviderToken(p.cred.Key, p.cred.KeyID, c.teamID, now)
	if err != nil {
		return "", err
	}
	p.value, p.issued = value, now
	return value, nil
}

func (c *apnsClient) expire(p *providerToken, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p.value == value {
		p.value = ""
	}
}

func signProviderToken(key *ecdsa.PrivateKey, keyID, teamID string, now time.Time) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": keyID})
	claims, _ := json.Marshal(map[string]any{"iss": teamID, "iat": now.Unix()})
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
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

type apsAlert struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

type alertPush struct {
	APS struct {
		Alert          apsAlert `json:"alert"`
		Sound          string   `json:"sound"`
		MutableContent int      `json:"mutable-content"`
	} `json:"aps"`
	Supaterm json.RawMessage `json:"supaterm"`
}

type challengePush struct {
	APS struct {
		Alert          apsAlert `json:"alert"`
		MutableContent int      `json:"mutable-content"`
	} `json:"aps"`
	Challenge struct {
		EnrollmentID string `json:"enrollmentId"`
		Code         string `json:"code"`
	} `json:"supatermChallenge"`
}

func alertBody(payload json.RawMessage) ([]byte, error) {
	var p alertPush
	p.APS.Alert = apsAlert{Title: "Supaterm", Body: "New activity"}
	p.APS.Sound = "default"
	p.APS.MutableContent = 1
	p.Supaterm = payload
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(b) > maxAPNsPayload {
		return nil, fmt.Errorf("APNs payload is %d bytes, over %d", len(b), maxAPNsPayload)
	}
	return b, nil
}

func challengeBody(enrollmentID, code string) []byte {
	var p challengePush
	p.APS.Alert = apsAlert{Title: "Supaterm", Body: "Finishing notification setup"}
	p.APS.MutableContent = 1
	p.Challenge.EnrollmentID = enrollmentID
	p.Challenge.Code = code
	b, _ := json.Marshal(p)
	return b
}
