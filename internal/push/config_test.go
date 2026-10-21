package push

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

func writeKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.p8")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	key := writeKey(t)
	c, err := LoadConfig(env(map[string]string{
		"PUSH_DATABASE":            "/var/lib/supaterm-push/push.sqlite",
		"APNS_TEAM_ID":             "TEAM123456",
		"APNS_TOPICS":              " com.supabit.supaterm, com.supabit.supaterm.dev,com.supabit.supaterm ",
		"APNS_PRODUCTION_KEY_ID":   "PRODKEY",
		"APNS_PRODUCTION_KEY_FILE": key,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != "127.0.0.1:8000" || !reflect.DeepEqual(c.Topics, []string{"com.supabit.supaterm", "com.supabit.supaterm.dev"}) {
		t.Fatalf("config = %+v", c)
	}
	prod, ok := c.Credentials[Production]
	if _, sandbox := c.Credentials[Sandbox]; !ok || sandbox || prod.KeyID != "PRODKEY" || prod.URL != "https://api.push.apple.com" || prod.Key == nil {
		t.Fatalf("credentials = %+v", c.Credentials)
	}
}

func TestLoadConfigRejectsInvalidValues(t *testing.T) {
	key := writeKey(t)
	valid := map[string]string{
		"PUSH_DATABASE":         "push.sqlite",
		"APNS_TEAM_ID":          "TEAM123456",
		"APNS_TOPICS":           "com.supabit.supaterm",
		"APNS_SANDBOX_KEY_ID":   "SANDBOXKEY",
		"APNS_SANDBOX_KEY_FILE": key,
	}
	cases := map[string]map[string]string{
		"PUSH_ADDR":             {"PUSH_ADDR": "8000"},
		"PUSH_DATABASE":         {"PUSH_DATABASE": ""},
		"APNS_TEAM_ID":          {"APNS_TEAM_ID": " "},
		"APNS_TOPICS":           {"APNS_TOPICS": " , "},
		"APNS_SANDBOX_KEY_FILE": {"APNS_SANDBOX_KEY_FILE": filepath.Join(t.TempDir(), "missing.p8")},
		"APNS_SANDBOX_KEY_ID":   {"APNS_SANDBOX_KEY_ID": ""},
		"at least one":          {"APNS_SANDBOX_KEY_ID": "", "APNS_SANDBOX_KEY_FILE": ""},
	}
	for want, override := range cases {
		kv := map[string]string{}
		maps.Copy(kv, valid)
		maps.Copy(kv, override)
		if _, err := LoadConfig(env(kv)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: got %v", override, err)
		}
	}
	notPEM := filepath.Join(t.TempDir(), "bad.p8")
	_ = os.WriteFile(notPEM, []byte("not a key"), 0o600)
	valid["APNS_SANDBOX_KEY_FILE"] = notPEM
	if _, err := LoadConfig(env(valid)); err == nil || !strings.Contains(err.Error(), "APNS_SANDBOX_KEY_FILE") {
		t.Errorf("malformed key: got %v", err)
	}
}
