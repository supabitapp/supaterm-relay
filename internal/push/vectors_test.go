package push

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// host-requests.json is copied from Supaterm's packages/shared/src/push/vectors.json,
// so a change to the host's request signing breaks this test instead of production sends.
func TestHostRequestVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/host-requests.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Host struct {
			PublicKey string `json:"publicKey"`
		} `json:"host"`
		Requests []struct {
			Method    string            `json:"method"`
			Path      string            `json:"path"`
			Timestamp int64             `json:"timestamp"`
			Body      string            `json:"body"`
			Headers   map[string]string `json:"headers"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Requests) == 0 {
		t.Fatal("no request vectors")
	}
	for _, v := range vectors.Requests {
		t.Run(v.Method+" "+v.Path, func(t *testing.T) {
			g := newGateway(t)
			g.now = time.UnixMilli(v.Timestamp)
			verify := func(body string) error {
				r := httptest.NewRequest(v.Method, v.Path, bytes.NewReader([]byte(body)))
				for name, value := range v.Headers {
					r.Header.Set(name, value)
				}
				h, err := g.s.host(r)
				if err == nil && b64u.EncodeToString(h.key) != vectors.Host.PublicKey {
					t.Fatalf("host key = %s, want %s", b64u.EncodeToString(h.key), vectors.Host.PublicKey)
				}
				return err
			}
			if err := verify(v.Body); err != nil {
				t.Fatalf("vector signature rejected: %v", err)
			}
			if verify(v.Body+" ") == nil {
				t.Fatal("tampered body accepted")
			}
		})
	}
}
