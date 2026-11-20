package push

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/supabitapp/supaterm-relay/internal/admission"
)

const (
	Sandbox    = "sandbox"
	Production = "production"
)

type Config struct {
	Addr           string
	PublicURL      string
	SealKeys       [][]byte
	RevocationFile string
	TrustedProxies []netip.Prefix
	APNs           APNsConfig
	FCM            *FCMCredential
}

type APNsConfig struct {
	TeamID string
	Topics []string
	Keys   map[string]APNsKey
}

type APNsKey struct {
	ID  string
	Key *ecdsa.PrivateKey
}

type FCMCredential struct {
	ProjectID   string
	ClientEmail string
	Key         *rsa.PrivateKey
	TokenURL    string
}

func LoadConfig(getenv func(string) string) (Config, error) {
	c := Config{Addr: "127.0.0.1:8000", APNs: APNsConfig{Keys: map[string]APNsKey{}}}
	if v := getenv("PUSH_ADDR"); v != "" {
		c.Addr = v
	}
	if err := validAddr(c.Addr); err != nil {
		return c, fmt.Errorf("PUSH_ADDR: %w", err)
	}
	publicURL, err := parsePublicURL(getenv("PUSH_PUBLIC_URL"))
	if err != nil {
		return c, fmt.Errorf("PUSH_PUBLIC_URL: %w", err)
	}
	c.PublicURL = publicURL
	if c.SealKeys, err = loadSealKeys(getenv("PUSH_SEAL_KEY_FILE")); err != nil {
		return c, fmt.Errorf("PUSH_SEAL_KEY_FILE: %w", err)
	}
	if c.RevocationFile = getenv("PUSH_REVOCATION_FILE"); c.RevocationFile == "" {
		return c, errors.New("PUSH_REVOCATION_FILE: required")
	}
	if c.TrustedProxies, err = admission.ParsePrefixes(getenv("PUSH_TRUSTED_PROXIES")); err != nil {
		return c, fmt.Errorf("PUSH_TRUSTED_PROXIES: %w", err)
	}
	if err := loadAPNs(getenv, &c.APNs); err != nil {
		return c, err
	}
	if file := getenv("FCM_CREDENTIALS_FILE"); file != "" {
		cred, err := loadFCMCredential(file)
		if err != nil {
			return c, fmt.Errorf("FCM_CREDENTIALS_FILE: %w", err)
		}
		c.FCM = &cred
	}
	if len(c.APNs.Keys) == 0 && c.FCM == nil {
		return c, errors.New("configure at least one APNs key or FCM_CREDENTIALS_FILE")
	}
	return c, nil
}

func parsePublicURL(v string) (string, error) {
	if v == "" {
		return "", errors.New("required")
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", err
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if (u.Scheme != "https" && u.Scheme != "http") || host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("must be an https origin, got %q", v)
	}
	if u.Scheme == "http" && !isLoopback(host) {
		return "", fmt.Errorf("must use https outside loopback, got %q", v)
	}
	defaultPort := "443"
	if u.Scheme == "http" {
		defaultPort = "80"
	}
	if port == defaultPort {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host, nil
}

func isLoopback(host string) bool {
	ip, err := netip.ParseAddr(host)
	return host == "localhost" || (err == nil && ip.IsLoopback())
}

func loadSealKeys(file string) ([][]byte, error) {
	if file == "" {
		return nil, errors.New("required")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var keys [][]byte
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(key) != 32 {
			return nil, errors.New("each line must be 32 bytes in standard base64")
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("no keys")
	}
	return keys, nil
}

func loadAPNs(getenv func(string) string, c *APNsConfig) error {
	for _, env := range []struct{ name, prefix string }{
		{Sandbox, "APNS_SANDBOX"},
		{Production, "APNS_PRODUCTION"},
	} {
		id := strings.TrimSpace(getenv(env.prefix + "_KEY_ID"))
		file := getenv(env.prefix + "_KEY_FILE")
		if id == "" && file == "" {
			continue
		}
		if id == "" || file == "" {
			return fmt.Errorf("%s_KEY_ID and %s_KEY_FILE: set both or neither", env.prefix, env.prefix)
		}
		key, err := loadAPNsKey(file)
		if err != nil {
			return fmt.Errorf("%s_KEY_FILE: %w", env.prefix, err)
		}
		c.Keys[env.name] = APNsKey{ID: id, Key: key}
	}
	if len(c.Keys) == 0 {
		return nil
	}
	if c.TeamID = strings.TrimSpace(getenv("APNS_TEAM_ID")); c.TeamID == "" {
		return errors.New("APNS_TEAM_ID: required with an APNs key")
	}
	for topic := range strings.SplitSeq(getenv("APNS_TOPICS"), ",") {
		if topic = strings.TrimSpace(topic); topic != "" && !slices.Contains(c.Topics, topic) {
			c.Topics = append(c.Topics, topic)
		}
	}
	if len(c.Topics) == 0 {
		return errors.New("APNS_TOPICS: required with an APNs key")
	}
	return nil
}

func loadAPNsKey(file string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	parsed, err := parsePKCS8(data)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve.Params().Name != "P-256" {
		return nil, errors.New("not a P-256 ECDSA key")
	}
	return key, nil
}

func parsePKCS8(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

func loadFCMCredential(file string) (FCMCredential, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return FCMCredential{}, err
	}
	var account struct {
		Type        string `json:"type"`
		ProjectID   string `json:"project_id"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(data, &account); err != nil {
		return FCMCredential{}, err
	}
	if account.Type != "service_account" || account.ProjectID == "" || account.ClientEmail == "" || account.TokenURI == "" {
		return FCMCredential{}, errors.New("not a service account key with project_id, client_email and token_uri")
	}
	parsed, err := parsePKCS8([]byte(account.PrivateKey))
	if err != nil {
		return FCMCredential{}, fmt.Errorf("private_key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return FCMCredential{}, errors.New("private_key: not an RSA key")
	}
	return FCMCredential{ProjectID: account.ProjectID, ClientEmail: account.ClientEmail, Key: key, TokenURL: account.TokenURI}, nil
}

func validAddr(v string) error {
	_, port, err := net.SplitHostPort(v)
	if err != nil {
		return err
	}
	if p, err := strconv.Atoi(port); err != nil || p < 0 || p > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}
