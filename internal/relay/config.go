package relay

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/supabitapp/supaterm-relay/internal/admission"
)

type Config struct {
	Addr                   string
	MaxMessageBytes        int
	MaxClientsPerHost      int
	MaxClientsPerHostPerIP int
	MaxConnectionsPerIP    int
	AuthTimeout            time.Duration
	PairTimeout            time.Duration
	DeliveryTimeout        time.Duration
	Heartbeat              time.Duration
	AdmissionRate          float64
	TrustedProxies         []netip.Prefix
	PrivateAddr            string
}

func (c Config) pongTimeout() time.Duration {
	return 2 * c.Heartbeat
}

func (c Config) admissionBurst() int {
	return max(1, int(c.AdmissionRate))
}

func LoadConfig(getenv func(string) string) (Config, error) {
	c := Config{Addr: "127.0.0.1:8080", AdmissionRate: 100}
	for _, name := range []string{"RELAY_ALLOWED_PEERS", "RELAY_PRIVATE_ALLOWED_PEERS", "RELAY_CLIENT_IP_HEADER"} {
		if getenv(name) != "" {
			return c, fmt.Errorf("%s: no longer supported", name)
		}
	}
	if v := getenv("RELAY_ADDR"); v != "" {
		c.Addr = v
	}
	if err := validAddr(c.Addr); err != nil {
		return c, fmt.Errorf("RELAY_ADDR: %w", err)
	}

	ints := []struct {
		name string
		def  int
		dst  *int
	}{
		{"RELAY_MAX_MESSAGE_BYTES", (32 << 20) - 14, &c.MaxMessageBytes},
		{"RELAY_MAX_CLIENTS_PER_HOST", 64, &c.MaxClientsPerHost},
		{"RELAY_MAX_CLIENTS_PER_HOST_PER_IP", 16, &c.MaxClientsPerHostPerIP},
		{"RELAY_MAX_CONNS_PER_IP", 128, &c.MaxConnectionsPerIP},
	}
	for _, f := range ints {
		n, err := positiveInt(getenv, f.name, f.def)
		if err != nil {
			return c, err
		}
		*f.dst = n
	}

	durations := []struct {
		name string
		def  int
		dst  *time.Duration
	}{
		{"RELAY_AUTH_TIMEOUT_MS", 5000, &c.AuthTimeout},
		{"RELAY_PAIR_TIMEOUT_MS", 5000, &c.PairTimeout},
		{"RELAY_DELIVERY_TIMEOUT_MS", 30000, &c.DeliveryTimeout},
		{"RELAY_HEARTBEAT_MS", 15000, &c.Heartbeat},
	}
	for _, f := range durations {
		n, err := positiveInt(getenv, f.name, f.def)
		if err != nil {
			return c, err
		}
		*f.dst = time.Duration(n) * time.Millisecond
	}

	if v := getenv("RELAY_ADMISSION_RATE"); v != "" {
		r, err := strconv.ParseFloat(v, 64)
		if err != nil || r <= 0 || r > 1e9 {
			return c, fmt.Errorf("RELAY_ADMISSION_RATE: must be a positive number, got %q", v)
		}
		c.AdmissionRate = r
	}

	proxies, err := admission.ParsePrefixes(getenv("RELAY_TRUSTED_PROXIES"))
	if err != nil {
		return c, fmt.Errorf("RELAY_TRUSTED_PROXIES: %w", err)
	}
	c.TrustedProxies = proxies

	if v := getenv("RELAY_PRIVATE_ADDR"); v != "" {
		if err := validAddr(v); err != nil {
			return c, fmt.Errorf("RELAY_PRIVATE_ADDR: %w", err)
		}
		c.PrivateAddr = v
	}
	return c, nil
}

func positiveInt(getenv func(string) string, name string, def int) (int, error) {
	v := getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: must be a positive integer, got %q", name, v)
	}
	return n, nil
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
