//go:build go1.27 && goexperiment.jsonv2

package relay

import (
	jsonv1 "encoding/json"
	jsonv2 "encoding/json/v2"
	"strings"
	"testing"
)

// Keep the API comparison out of the relay binary and available without raising
// the module's minimum Go version. Go 1.27's v1 API already uses the v2 engine;
// these benchmarks compare API defaults, not old versus new implementations.
func BenchmarkJSONControl(b *testing.B) {
	message := controlMessage{
		Type: "incoming", ConnectionID: strings.Repeat("a", 22), Token: strings.Repeat("b", 43),
	}
	for _, codec := range []struct {
		name    string
		marshal func(any) ([]byte, error)
	}{
		{"v1", jsonv1.Marshal},
		{"v2", func(v any) ([]byte, error) { return jsonv2.Marshal(v) }},
	} {
		b.Run(codec.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := codec.marshal(message); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJSONAuth(b *testing.B) {
	data := []byte(`{"type":"authenticate","signature":"` + strings.Repeat("a", 86) + `"}`)
	for _, codec := range []struct {
		name      string
		unmarshal func([]byte, any) error
	}{
		{"v1", jsonv1.Unmarshal},
		{"v2", func(data []byte, v any) error { return jsonv2.Unmarshal(data, v) }},
	} {
		b.Run(codec.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var auth struct {
					Type      string `json:"type"`
					Signature string `json:"signature"`
				}
				if err := codec.unmarshal(data, &auth); err != nil {
					b.Fatal(err)
				}
				if auth.Type != "authenticate" || len(auth.Signature) != 86 {
					b.Fatal("incorrect decoded auth")
				}
			}
		})
	}
}
