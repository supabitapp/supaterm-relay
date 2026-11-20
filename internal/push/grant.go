package push

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

const (
	grantLifetime     = 30 * 24 * time.Hour
	sealVersion       = 1
	maxEndpointLength = 2048
	pushPath          = "/v1/push/"
)

var sealContext = []byte("supaterm-push endpoint")

type grant struct {
	ID            string `json:"g"`
	Platform      string `json:"p"`
	Token         string `json:"t"`
	Topic         string `json:"o,omitempty"`
	Environment   string `json:"e,omitempty"`
	HostKey       []byte `json:"h"`
	ManagementKey []byte `json:"m"`
	IssuedAt      int64  `json:"i"`
	ExpiresAt     int64  `json:"x"`
}

type subscription struct {
	Endpoint   string `json:"endpoint"`
	ExpiresAt  int64  `json:"expiresAt"`
	RenewAfter int64  `json:"renewAfter"`
}

func newGrantID() string {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return hex.EncodeToString(id)
}

func (g grant) expired(now time.Time) bool {
	return now.Unix() >= g.ExpiresAt
}

func (g grant) renewable(now time.Time) bool {
	return now.Unix() >= g.renewAfter()
}

func (g grant) renewAfter() int64 {
	return g.IssuedAt + int64(grantLifetime/time.Second)/2
}

type sealer struct {
	origin string
	keys   []sealKey
}

type sealKey struct {
	id   [4]byte
	aead cipher.AEAD
}

func newSealer(raw [][]byte, origin string) sealer {
	keys := make([]sealKey, len(raw))
	for i, key := range raw {
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(key)
		keys[i] = sealKey{id: [4]byte(sum[:4]), aead: aead}
	}
	return sealer{origin: origin, keys: keys}
}

func (s sealer) issue(g grant, now time.Time) (grant, subscription) {
	g.IssuedAt = now.Unix()
	g.ExpiresAt = now.Add(grantLifetime).Unix()
	plaintext, err := json.Marshal(g)
	if err != nil {
		panic(err)
	}
	return g, subscription{
		Endpoint:   s.origin + pushPath + s.seal(plaintext),
		ExpiresAt:  g.ExpiresAt,
		RenewAfter: g.renewAfter(),
	}
}

func (s sealer) grant(sealed string) (grant, bool) {
	plaintext, ok := s.open(sealed)
	if !ok {
		return grant{}, false
	}
	var g grant
	return g, json.Unmarshal(plaintext, &g) == nil
}

func (s sealer) grantAt(endpoint string) (grant, bool) {
	sealed, ok := strings.CutPrefix(endpoint, s.origin+pushPath)
	if !ok {
		return grant{}, false
	}
	return s.grant(sealed)
}

func (s sealer) seal(plaintext []byte) string {
	k := s.keys[0]
	out := append([]byte{sealVersion}, k.id[:]...)
	aad := append(bytes.Clone(sealContext), out...)
	nonce := make([]byte, k.aead.NonceSize())
	_, _ = rand.Read(nonce)
	out = append(out, nonce...)
	return base64.RawURLEncoding.EncodeToString(k.aead.Seal(out, nonce, plaintext, aad))
}

func (s sealer) open(sealed string) ([]byte, bool) {
	if len(sealed) > maxEndpointLength {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	const header = 5
	if err != nil || len(raw) < header || raw[0] != sealVersion {
		return nil, false
	}
	for _, k := range s.keys {
		if !bytes.Equal(k.id[:], raw[1:header]) {
			continue
		}
		body := raw[header:]
		if len(body) < k.aead.NonceSize()+k.aead.Overhead() {
			return nil, false
		}
		aad := append(bytes.Clone(sealContext), raw[:header]...)
		plaintext, err := k.aead.Open(nil, body[:k.aead.NonceSize()], body[k.aead.NonceSize():], aad)
		return plaintext, err == nil
	}
	return nil, false
}
