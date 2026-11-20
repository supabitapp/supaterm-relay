package push

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func pemKey(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func baseEnv(t *testing.T) map[string]string {
	t.Helper()
	seal := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	return map[string]string{
		"PUSH_PUBLIC_URL":          "https://Push.Supaterm.com:443/",
		"PUSH_SEAL_KEY_FILE":       writeFile(t, "seal", "\n"+seal+"\n"+seal+"\n"),
		"PUSH_REVOCATION_FILE":     "/var/lib/supaterm-push/revocations",
		"APNS_TEAM_ID":             "TEAM123456",
		"APNS_TOPICS":              "com.supaterm.mobile, com.supaterm.mobile.dev,com.supaterm.mobile",
		"APNS_SANDBOX_KEY_ID":      "KEY1234567",
		"APNS_SANDBOX_KEY_FILE":    writeFile(t, "sandbox.p8", pemKey(t, newKey(t))),
		"PUSH_TRUSTED_PROXIES":     "127.0.0.1/32",
		"APNS_PRODUCTION_KEY_ID":   "",
		"APNS_PRODUCTION_KEY_FILE": "",
	}
}

func load(env map[string]string) (Config, error) {
	return LoadConfig(func(name string) string { return env[name] })
}

func TestLoadConfig(t *testing.T) {
	env := baseEnv(t)
	env["FCM_CREDENTIALS_FILE"] = writeFile(t, "fcm.json", serviceAccount(t, "service_account"))
	c, err := load(env)
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != "127.0.0.1:8000" || c.PublicURL != "https://push.supaterm.com" || len(c.SealKeys) != 2 || len(c.TrustedProxies) != 1 {
		t.Fatalf("config %+v", c)
	}
	if strings.Join(c.APNs.Topics, ",") != "com.supaterm.mobile,com.supaterm.mobile.dev" || c.APNs.Keys[Sandbox].ID != "KEY1234567" || len(c.APNs.Keys) != 1 {
		t.Fatalf("apns %+v", c.APNs)
	}
	if c.FCM == nil || c.FCM.ProjectID != "supaterm-test" || c.FCM.TokenURL != "https://oauth2.googleapis.com/token" {
		t.Fatalf("fcm %+v", c.FCM)
	}

	env["PUSH_PUBLIC_URL"] = "http://[::1]:8000"
	if c, err := load(env); err != nil || c.PublicURL != "http://[::1]:8000" {
		t.Fatalf("loopback origin: %q, %v", c.PublicURL, err)
	}

	fcmOnly := baseEnv(t)
	for _, name := range []string{"APNS_TEAM_ID", "APNS_TOPICS", "APNS_SANDBOX_KEY_ID", "APNS_SANDBOX_KEY_FILE"} {
		delete(fcmOnly, name)
	}
	fcmOnly["FCM_CREDENTIALS_FILE"] = env["FCM_CREDENTIALS_FILE"]
	if c, err := load(fcmOnly); err != nil || len(c.APNs.Keys) != 0 || c.FCM == nil {
		t.Fatalf("FCM-only config: %+v, %v", c, err)
	}
}

func TestLoadConfigRejectsInvalidValues(t *testing.T) {
	cases := map[string]map[string]string{
		"PUSH_ADDR":             {"PUSH_ADDR": "8000"},
		"PUSH_PUBLIC_URL":       {"PUSH_PUBLIC_URL": "https://push.supaterm.com/v1"},
		"outside loopback":      {"PUSH_PUBLIC_URL": "http://push.supaterm.com"},
		"PUSH_SEAL_KEY_FILE":    {"PUSH_SEAL_KEY_FILE": writeFile(t, "short", base64.StdEncoding.EncodeToString([]byte("short")))},
		"PUSH_REVOCATION_FILE":  {"PUSH_REVOCATION_FILE": ""},
		"PUSH_TRUSTED_PROXIES":  {"PUSH_TRUSTED_PROXIES": "10.0.0.0/99"},
		"APNS_SANDBOX_KEY_ID":   {"APNS_SANDBOX_KEY_ID": ""},
		"APNS_PRODUCTION":       {"APNS_PRODUCTION_KEY_ID": "KEY"},
		"APNS_TEAM_ID":          {"APNS_TEAM_ID": " "},
		"APNS_TOPICS":           {"APNS_TOPICS": ","},
		"APNS_SANDBOX_KEY_FILE": {"APNS_SANDBOX_KEY_FILE": writeFile(t, "rsa.p8", pemKey(t, fcmKey()))},
		"FCM_CREDENTIALS_FILE":  {"FCM_CREDENTIALS_FILE": writeFile(t, "user.json", serviceAccount(t, "authorized_user"))},
		"at least one APNs key": {"APNS_SANDBOX_KEY_ID": "", "APNS_SANDBOX_KEY_FILE": ""},
	}
	for want, overrides := range cases {
		env := baseEnv(t)
		maps.Copy(env, overrides)
		if _, err := load(env); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: got %v, want an error about %s", overrides, err, want)
		}
	}
}

func serviceAccount(t *testing.T, kind string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]string{
		"type":         kind,
		"project_id":   "supaterm-test",
		"client_email": "push@supaterm-test.iam.gserviceaccount.com",
		"private_key":  pemKey(t, fcmKey()),
		"token_uri":    "https://oauth2.googleapis.com/token",
	})
	return string(b)
}
