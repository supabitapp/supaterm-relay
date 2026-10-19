package relay

import (
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func BenchmarkForward(b *testing.B) {
	for _, size := range []int{64, 1024, 64 << 10} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			cfg, err := LoadConfig(env(nil))
			if err != nil {
				b.Fatal(err)
			}
			s := New(cfg)
			listener := httptest.NewServer(s.http.Handler)
			b.Cleanup(listener.Close)
			h := registerHost(b, "ws"+strings.TrimPrefix(listener.URL, "http"))
			client, host := openPair(b, h)
			payload := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				if err := client.WriteMessage(websocket.BinaryMessage, payload); err != nil {
					b.Fatal(err)
				}
				typ, reader, err := host.NextReader()
				if err != nil {
					b.Fatal(err)
				}
				n, err := io.Copy(io.Discard, reader)
				if err != nil || typ != websocket.BinaryMessage || n != int64(size) {
					b.Fatalf("forwarded type=%d bytes=%d err=%v", typ, n, err)
				}
			}
		})
	}
}

func BenchmarkTopHosts(b *testing.B) {
	for _, count := range []int{20, 1000, 50000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			s := &Server{hosts: make(map[string]*host, count)}
			for i := range count {
				h := &host{}
				h.bytesIn.Store(int64(i + 1))
				s.hosts[fmt.Sprintf("%016x%048x", i, i)] = h
			}
			b.ReportAllocs()
			for b.Loop() {
				if got := s.topHosts(); len(got) != min(count, topHostsReported) {
					b.Fatal("incorrect host count")
				}
			}
		})
	}
}

// Compare the same wire fields without conflating a codec change with replacing
// maps by a fixed schema. The map variant represents the original control path.
func BenchmarkControlFrame(b *testing.B) {
	id, token := strings.Repeat("a", 22), strings.Repeat("b", 43)
	b.Run("map", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			textFrame(map[string]string{"type": "incoming", "connectionId": id, "token": token})
		}
	})
	b.Run("struct", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			textFrame(controlMessage{Type: "incoming", ConnectionID: id, Token: token})
		}
	})
}

func BenchmarkControlQueue(b *testing.B) {
	q := newQueue(maxQueueBytes, maxQueueMessages)
	f := frame{typ: websocket.TextMessage, data: []byte(`{"type":"closed","connectionId":"example"}`)}
	b.ReportAllocs()
	for b.Loop() {
		if !q.push(f) {
			b.Fatal("queue full")
		}
		out, _, ok := q.next()
		if !ok {
			b.Fatal("queue empty")
		}
		q.release(out)
	}
}

func BenchmarkDecodeB64(b *testing.B) {
	for _, size := range []int{32, 64} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			encoded := randomB64(size)
			b.ReportAllocs()
			for b.Loop() {
				if _, ok := decodeB64(encoded, size); !ok {
					b.Fatal("invalid encoding")
				}
			}
		})
	}
}
