package push

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"time"
)

const (
	maxHostTokenLifetime    = time.Hour
	maxPhoneRequestLifetime = 5 * time.Minute
	clockSkew               = time.Minute
	maxJWSLength            = 4096
)

type phoneRequest struct {
	Audience string `json:"aud"`
	Action   string `json:"act"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	Endpoint string `json:"endpoint"`
	Token    string `json:"token,omitempty"`
	Request  string `json:"request,omitempty"`
}

func parseP256(encoded string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(encoded, "="))
	if err != nil {
		return nil, false
	}
	_, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	return raw, err == nil
}

func verifyES256(rawKey []byte, token string) ([]byte, bool) {
	if len(token) > maxJWSLength || strings.Count(token, ".") != 2 {
		return nil, false
	}
	dot := strings.LastIndexByte(token, '.')
	input, encodedSig := token[:dot], token[dot+1:]
	encodedHeader, encodedPayload, _ := strings.Cut(input, ".")
	var header struct {
		Alg string `json:"alg"`
	}
	if !decodeSegment(encodedHeader, &header) || header.Alg != "ES256" {
		return nil, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(encodedSig)
	if err != nil || len(sig) != 64 {
		return nil, false
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), rawKey)
	if err != nil {
		return nil, false
	}
	digest := sha256.Sum256([]byte(input))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	return payload, err == nil
}

func decodeSegment(segment string, v any) bool {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	return err == nil && json.Unmarshal(raw, v) == nil
}

func parseVAPID(header string) (token string, key []byte, ok bool) {
	scheme, params, found := strings.Cut(strings.TrimSpace(header), " ")
	if !found || !strings.EqualFold(scheme, "vapid") {
		return "", nil, false
	}
	for param := range strings.SplitSeq(params, ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(param), "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "t":
			token = strings.TrimSpace(value)
		case "k":
			key, ok = parseP256(strings.TrimSpace(value))
			if !ok {
				return "", nil, false
			}
		}
	}
	return token, key, token != "" && key != nil
}

func hostAuthorized(g grant, authorization, audience string, now time.Time) bool {
	token, key, ok := parseVAPID(authorization)
	if !ok || !bytes.Equal(key, g.HostKey) {
		return false
	}
	payload, ok := verifyES256(g.HostKey, token)
	if !ok {
		return false
	}
	var claims struct {
		Audience string `json:"aud"`
		Expires  int64  `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return false
	}
	exp := time.Unix(claims.Expires, 0)
	return claims.Audience == audience && exp.After(now) && !exp.After(now.Add(maxHostTokenLifetime+clockSkew))
}

func verifyPhoneRequest(s sealer, jws, action string, now time.Time) (phoneRequest, grant, error) {
	parts := strings.Split(jws, ".")
	var req phoneRequest
	if len(jws) > maxJWSLength || len(parts) != 3 || !decodeSegment(parts[1], &req) {
		return req, grant{}, errInvalidRequest
	}
	g, ok := s.grantAt(req.Endpoint)
	if !ok {
		return req, grant{}, errEndpointInvalid
	}
	if _, ok := verifyES256(g.ManagementKey, jws); !ok {
		return req, grant{}, errUnauthorized
	}
	issued, expires := time.Unix(req.IssuedAt, 0), time.Unix(req.Expires, 0)
	if req.Audience != s.origin || req.Action != action || !expires.After(now) || issued.After(now.Add(clockSkew)) || expires.Sub(issued) > maxPhoneRequestLifetime {
		return req, grant{}, errUnauthorized
	}
	return req, g, nil
}
