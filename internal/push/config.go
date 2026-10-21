package push

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
)

const (
	Sandbox    = "sandbox"
	Production = "production"
)

var defaultAPNsURLs = map[string]string{
	Sandbox:    "https://api.sandbox.push.apple.com",
	Production: "https://api.push.apple.com",
}

type Credential struct {
	KeyID string
	Key   *ecdsa.PrivateKey
	URL   string
}

type Config struct {
	Addr        string
	Database    string
	TeamID      string
	Topics      []string
	Credentials map[string]Credential
}

func LoadConfig(getenv func(string) string) (Config, error) {
	c := Config{Addr: "127.0.0.1:8000", Credentials: map[string]Credential{}}
	if v := getenv("PUSH_ADDR"); v != "" {
		c.Addr = v
	}
	if err := validAddr(c.Addr); err != nil {
		return c, fmt.Errorf("PUSH_ADDR: %w", err)
	}
	if c.Database = getenv("PUSH_DATABASE"); c.Database == "" {
		return c, errors.New("PUSH_DATABASE: required")
	}
	if c.TeamID = strings.TrimSpace(getenv("APNS_TEAM_ID")); c.TeamID == "" {
		return c, errors.New("APNS_TEAM_ID: required")
	}
	for topic := range strings.SplitSeq(getenv("APNS_TOPICS"), ",") {
		if topic = strings.TrimSpace(topic); topic != "" && !slices.Contains(c.Topics, topic) {
			c.Topics = append(c.Topics, topic)
		}
	}
	if len(c.Topics) == 0 {
		return c, errors.New("APNS_TOPICS: required")
	}
	for _, env := range []struct{ name, prefix string }{
		{Sandbox, "APNS_SANDBOX"},
		{Production, "APNS_PRODUCTION"},
	} {
		keyID := strings.TrimSpace(getenv(env.prefix + "_KEY_ID"))
		file := getenv(env.prefix + "_KEY_FILE")
		if keyID == "" && file == "" {
			continue
		}
		if keyID == "" || file == "" {
			return c, fmt.Errorf("%s_KEY_ID and %s_KEY_FILE: set both or neither", env.prefix, env.prefix)
		}
		key, err := loadKey(file)
		if err != nil {
			return c, fmt.Errorf("%s_KEY_FILE: %w", env.prefix, err)
		}
		c.Credentials[env.name] = Credential{KeyID: keyID, Key: key, URL: defaultAPNsURLs[env.name]}
	}
	if len(c.Credentials) == 0 {
		return c, errors.New("APNS_SANDBOX_KEY_ID or APNS_PRODUCTION_KEY_ID: at least one APNs key is required")
	}
	return c, nil
}

func loadKey(file string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve.Params().Name != "P-256" {
		return nil, errors.New("not a P-256 ECDSA key")
	}
	return key, nil
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
