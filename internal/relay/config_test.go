package relay

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

func TestLoadConfigDefaults(t *testing.T) {
	c, err := LoadConfig(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		Addr:                   "127.0.0.1:8080",
		MaxMessageBytes:        (32 << 20) - 14,
		MaxClientsPerHost:      64,
		MaxClientsPerHostPerIP: 16,
		MaxConnectionsPerIP:    128,
		AuthTimeout:            5 * time.Second,
		PairTimeout:            5 * time.Second,
		DeliveryTimeout:        30 * time.Second,
		Heartbeat:              15 * time.Second,
		AdmissionRate:          100,
	}
	if !reflect.DeepEqual(c, want) || c.admissionBurst() != 100 {
		t.Fatalf("defaults = %+v, want %+v", c, want)
	}
}

func TestLoadConfigRejectsInvalidValues(t *testing.T) {
	cases := map[string]string{
		"RELAY_ADDR":                        "nonsense",
		"RELAY_MAX_MESSAGE_BYTES":           "abc",
		"RELAY_MAX_CLIENTS_PER_HOST":        "x",
		"RELAY_MAX_CLIENTS_PER_HOST_PER_IP": "0",
		"RELAY_MAX_CONNS_PER_IP":            "-1",
		"RELAY_AUTH_TIMEOUT_MS":             "0",
		"RELAY_PAIR_TIMEOUT_MS":             "soon",
		"RELAY_DELIVERY_TIMEOUT_MS":         "0",
		"RELAY_HEARTBEAT_MS":                "1e3",
		"RELAY_ADMISSION_RATE":              "0",
		"RELAY_TRUSTED_PROXIES":             "10.0.0.0/99",
		"RELAY_PRIVATE_ADDR":                "9090",
		"RELAY_ALLOWED_PEERS":               "10.0.0.0/8",
		"RELAY_PRIVATE_ALLOWED_PEERS":       "10.0.0.0/8",
		"RELAY_CLIENT_IP_HEADER":            "X-Real-IP",
	}
	for name, value := range cases {
		_, err := LoadConfig(env(map[string]string{name: value}))
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s=%q: got %v", name, value, err)
		}
	}
}
