// Package supaterm reproduces the relay-facing behavior of Supaterm's host and
// client: packages/shared/src/relay/protocol.ts, tunnel.ts, and
// apps/server/src/relay/transport.ts in github.com/supabitapp/supaterm.
package supaterm

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/supabitapp/supaterm-relay/internal/endpoint"
)

const (
	tunnelVersion     = 2
	maxHandshakeBytes = 4096
	recordOverhead    = 8 + chacha20poly1305.Overhead
	addressSuffix     = ".relay.supaterm.alt"
	legacySuffix      = ".relay.supaterm.invalid"
)

var addressKey = regexp.MustCompile(`^[0-9a-f]{32}\.[0-9a-f]{32}$`)

func Address(identity ed25519.PublicKey) string {
	h := hex.EncodeToString(identity)
	return "https://" + h[:32] + "." + h[32:] + addressSuffix + "/"
}

func ParseAddress(address string) (ed25519.PublicKey, error) {
	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	host := strings.ToLower(u.Hostname())
	key, ok := strings.CutSuffix(host, addressSuffix)
	if !ok {
		key, ok = strings.CutSuffix(host, legacySuffix)
	}
	if !ok {
		return nil, errors.New("not a relay address")
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "https" && scheme != "wss") || (u.Port() != "" && u.Port() != "443") || u.User != nil {
		return nil, errors.New("invalid relay address")
	}
	if !addressKey.MatchString(key) {
		return nil, errors.New("invalid relay identity")
	}
	return hex.DecodeString(strings.Replace(key, ".", "", 1))
}

type hello struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
	Key     string `json:"key"`
}

type welcome struct {
	Type      string `json:"type"`
	Version   int    `json:"version"`
	Key       string `json:"key"`
	Signature string `json:"signature"`
}

var base64URL = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

func decodeBase64(s string) ([]byte, error) {
	if !base64URL.MatchString(s) {
		return nil, errors.New("invalid relay encoding")
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func decodeKey(s string) ([]byte, error) {
	key, err := decodeBase64(s)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid relay key")
	}
	return key, nil
}

func transcript(identity, client, host []byte) []byte {
	return bytes.Join([][]byte{[]byte(fmt.Sprintf("supaterm-tunnel-v%d\n", tunnelVersion)), identity, client, host}, nil)
}

type Cipher struct {
	send, recv     cipher.AEAD
	sent, received uint64
}

func newCipher(shared, context []byte, host bool) (*Cipher, error) {
	salt := sha256.Sum256(context)
	keys, err := hkdf.Key(sha256.New, shared, salt[:], "supaterm-tunnel-traffic-v1", 64)
	if err != nil {
		return nil, err
	}
	sendKey, recvKey := keys[:32], keys[32:]
	if host {
		sendKey, recvKey = recvKey, sendKey
	}
	send, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, err
	}
	recv, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, err
	}
	return &Cipher{send: send, recv: recv}, nil
}

func (c *Cipher) Seal(plain []byte) []byte {
	var nonce [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], c.sent)
	c.sent++
	return c.send.Seal(append(make([]byte, 0, recordOverhead+len(plain)), nonce[4:]...), nonce[:], plain, nil)
}

func (c *Cipher) Open(record []byte, maxPlain int) ([]byte, error) {
	if len(record) < recordOverhead || len(record) > maxPlain+recordOverhead {
		return nil, errors.New("invalid relay frame")
	}
	if binary.BigEndian.Uint64(record) != c.received {
		return nil, errors.New("relay frame out of order")
	}
	var nonce [chacha20poly1305.NonceSize]byte
	copy(nonce[4:], record[:8])
	plain, err := c.recv.Open(nil, nonce[:], record[8:], nil)
	if err != nil {
		return nil, err
	}
	c.received++
	return plain, nil
}

type ClientHandshake struct {
	identity ed25519.PublicKey
	secret   *ecdh.PrivateKey
	Hello    []byte
}

func NewClientHandshake(identity ed25519.PublicKey, random io.Reader) (*ClientHandshake, error) {
	secret, err := x25519Key(random)
	if err != nil {
		return nil, err
	}
	msg, _ := json.Marshal(hello{Type: "hello", Version: tunnelVersion, Key: endpoint.B64(secret.PublicKey().Bytes())})
	return &ClientHandshake{identity: identity, secret: secret, Hello: msg}, nil
}

func (h *ClientHandshake) Finish(raw []byte) (*Cipher, error) {
	var w welcome
	if err := json.Unmarshal(raw, &w); err != nil || w.Type != "welcome" || w.Key == "" || w.Signature == "" {
		return nil, errors.New("invalid relay welcome")
	}
	if w.Version != tunnelVersion {
		return nil, errors.New("relay protocol mismatch")
	}
	hostKey, err := decodeKey(w.Key)
	if err != nil {
		return nil, err
	}
	context := transcript(h.identity, h.secret.PublicKey().Bytes(), hostKey)
	sig, err := decodeBase64(w.Signature)
	if err != nil || !ed25519.Verify(h.identity, context, sig) {
		return nil, errors.New("relay host identity mismatch")
	}
	return derive(h.secret, hostKey, context, false)
}

func AcceptClientHandshake(raw []byte, identity ed25519.PrivateKey, random io.Reader) (welcomeMsg []byte, c *Cipher, err error) {
	var m hello
	if err := json.Unmarshal(raw, &m); err != nil || m.Type != "hello" || m.Version != tunnelVersion || m.Key == "" {
		return nil, nil, errors.New("invalid relay hello")
	}
	clientKey, err := decodeKey(m.Key)
	if err != nil {
		return nil, nil, err
	}
	secret, err := x25519Key(random)
	if err != nil {
		return nil, nil, err
	}
	public := secret.PublicKey().Bytes()
	context := transcript(identity.Public().(ed25519.PublicKey), clientKey, public)
	if c, err = derive(secret, clientKey, context, true); err != nil {
		return nil, nil, err
	}
	welcomeMsg, _ = json.Marshal(welcome{
		Type:      "welcome",
		Version:   m.Version,
		Key:       endpoint.B64(public),
		Signature: endpoint.B64(ed25519.Sign(identity, context)),
	})
	return welcomeMsg, c, nil
}

func x25519Key(random io.Reader) (*ecdh.PrivateKey, error) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(seed)
}

func derive(secret *ecdh.PrivateKey, peer, context []byte, host bool) (*Cipher, error) {
	pub, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	shared, err := secret.ECDH(pub)
	if err != nil {
		return nil, err
	}
	return newCipher(shared, context, host)
}
