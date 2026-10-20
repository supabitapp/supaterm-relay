package supaterm

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type vectors struct {
	Identity     string `json:"identity"`
	ClientSecret string `json:"clientSecret"`
	Address      string `json:"address"`
	Transcript   string `json:"transcript"`
	Hello        string `json:"hello"`
	Welcome      string `json:"welcome"`
	Records      []struct {
		Plain  string `json:"plain"`
		Client string `json:"client"`
		Host   string `json:"host"`
	} `json:"records"`
}

func sequence(start byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSupatermVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	identity := ed25519.NewKeyFromSeed(sequence(0))
	pub := identity.Public().(ed25519.PublicKey)
	if got := hex.EncodeToString(pub); got != v.Identity {
		t.Fatalf("identity %s, want %s", got, v.Identity)
	}
	if got := Address(pub); got != v.Address {
		t.Fatalf("address %s, want %s", got, v.Address)
	}
	parsed, err := ParseAddress(v.Address)
	if err != nil || !bytes.Equal(parsed, pub) {
		t.Fatalf("parse address: %x %v", parsed, err)
	}

	client, err := NewClientHandshake(pub, bytes.NewReader(sequence(32)))
	if err != nil {
		t.Fatal(err)
	}
	if string(client.Hello) != v.Hello {
		t.Fatalf("hello %s, want %s", client.Hello, v.Hello)
	}
	welcome, hostCipher, err := AcceptClientHandshake(client.Hello, identity, bytes.NewReader(sequence(64)))
	if err != nil {
		t.Fatal(err)
	}
	if string(welcome) != v.Welcome {
		t.Fatalf("welcome %s, want %s", welcome, v.Welcome)
	}
	clientCipher, err := client.Finish(welcome)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range v.Records {
		plain := unhex(t, r.Plain)
		if got := hex.EncodeToString(clientCipher.Seal(plain)); got != r.Client {
			t.Fatalf("record %d client seal %s, want %s", i, got, r.Client)
		}
		if got := hex.EncodeToString(hostCipher.Seal(plain)); got != r.Host {
			t.Fatalf("record %d host seal %s, want %s", i, got, r.Host)
		}
	}

	opener, _ := freshPair(t, identity)
	for i, r := range v.Records {
		got, err := opener.host.Open(unhex(t, r.Client), MaxPlainBytes)
		if err != nil || !bytes.Equal(got, unhex(t, r.Plain)) {
			t.Fatalf("record %d host open: %x %v", i, got, err)
		}
		got, err = opener.client.Open(unhex(t, r.Host), MaxPlainBytes)
		if err != nil || !bytes.Equal(got, unhex(t, r.Plain)) {
			t.Fatalf("record %d client open: %x %v", i, got, err)
		}
	}
}

type cipherPair struct{ client, host *Cipher }

func freshPair(t *testing.T, identity ed25519.PrivateKey) (cipherPair, []byte) {
	t.Helper()
	client, err := NewClientHandshake(identity.Public().(ed25519.PublicKey), bytes.NewReader(sequence(32)))
	if err != nil {
		t.Fatal(err)
	}
	welcome, host, err := AcceptClientHandshake(client.Hello, identity, bytes.NewReader(sequence(64)))
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.Finish(welcome)
	if err != nil {
		t.Fatal(err)
	}
	return cipherPair{c, host}, welcome
}

func TestCipherRejectsTamperingReplayAndReordering(t *testing.T) {
	identity := ed25519.NewKeyFromSeed(make([]byte, 32))
	p, _ := freshPair(t, identity)
	first, second := p.client.Seal([]byte("one")), p.client.Seal([]byte("two"))
	if _, err := p.host.Open(second, MaxPlainBytes); err == nil {
		t.Fatal("opened a record out of order")
	}
	flipped := bytes.Clone(first)
	flipped[len(flipped)-1] ^= 1
	if _, err := p.host.Open(flipped, MaxPlainBytes); err == nil {
		t.Fatal("opened a modified record")
	}
	if _, err := p.host.Open(first, MaxPlainBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := p.host.Open(first, MaxPlainBytes); err == nil {
		t.Fatal("opened a replayed record")
	}
	if _, err := p.host.Open(second[:recordOverhead-1], MaxPlainBytes); err == nil {
		t.Fatal("opened a truncated record")
	}
	if _, err := p.host.Open(make([]byte, MaxRecordBytes+1), MaxPlainBytes); err == nil {
		t.Fatal("opened an oversized record")
	}
}

func TestHandshakeRejectsKeysTheTypeScriptDecoderRejects(t *testing.T) {
	identity := ed25519.NewKeyFromSeed(make([]byte, 32))
	client, err := NewClientHandshake(identity.Public().(ed25519.PublicKey), bytes.NewReader(sequence(32)))
	if err != nil {
		t.Fatal(err)
	}
	var m hello
	_ = json.Unmarshal(client.Hello, &m)
	for _, key := range []string{m.Key[:20] + "\n" + m.Key[20:], m.Key + "=", m.Key[:42] + "+"} {
		raw, _ := json.Marshal(hello{Type: "hello", Version: tunnelVersion, Key: key})
		if _, _, err := AcceptClientHandshake(raw, identity, bytes.NewReader(sequence(64))); err == nil {
			t.Errorf("accepted hello key %q", key)
		}
	}
}

func TestClientRejectsAnImpostorHost(t *testing.T) {
	identity := ed25519.NewKeyFromSeed(make([]byte, 32))
	impostor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	client, err := NewClientHandshake(identity.Public().(ed25519.PublicKey), bytes.NewReader(sequence(32)))
	if err != nil {
		t.Fatal(err)
	}
	welcome, _, err := AcceptClientHandshake(client.Hello, impostor, bytes.NewReader(sequence(64)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Finish(welcome); err == nil {
		t.Fatal("accepted a welcome signed by another identity")
	}
}

func TestParseAddressAcceptsLegacySuffixAndRejectsLookalikes(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	h := hex.EncodeToString(pub)
	for _, good := range []string{
		"https://" + h[:32] + "." + h[32:] + ".relay.supaterm.invalid/",
		"https://" + strings.ToUpper(h[:32]+"."+h[32:]) + ".RELAY.SUPATERM.ALT/",
		"https://" + h[:32] + "." + h[32:] + ".relay.supaterm.alt:443/",
		"wss://" + h[:32] + "." + h[32:] + ".relay.supaterm.alt",
	} {
		if got, err := ParseAddress(good); err != nil || !bytes.Equal(got, pub) {
			t.Errorf("rejected %s: %v", good, err)
		}
	}
	for _, bad := range []string{
		"http://" + h[:32] + "." + h[32:] + ".relay.supaterm.alt/",
		"https://" + h[:32] + "." + h[32:] + ".relay.supaterm.alt:8443/",
		"https://user@" + h[:32] + "." + h[32:] + ".relay.supaterm.alt/",
		"https://" + h + ".relay.supaterm.alt/",
		"https://example.com/",
	} {
		if _, err := ParseAddress(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
