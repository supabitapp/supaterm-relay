package relay

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestDecodeB64Canonical(t *testing.T) {
	if _, ok := decodeB64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32); !ok {
		t.Fatal("canonical rejected")
	}
	for _, s := range []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AAAAAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAA"} {
		if _, ok := decodeB64(s, 32); ok {
			t.Fatalf("accepted %q", s)
		}
	}
}

func TestDecodeB64RejectsNoncanonicalLengthsAndNewlines(t *testing.T) {
	for _, size := range []int{32, 64} {
		canonical := base64.RawURLEncoding.EncodeToString(make([]byte, size))
		if _, ok := decodeB64(canonical, size); !ok {
			t.Fatalf("rejected canonical %d-byte value", size)
		}
		for _, invalid := range []string{
			canonical + "=", canonical[:len(canonical)-1], canonical + "AAAA",
			canonical[:10] + "\r\n" + canonical[10:],
			canonical[:10] + "\n" + canonical[11:],
			canonical[:10] + "\r" + canonical[11:],
			canonical[:len(canonical)-1] + "B",
		} {
			if _, ok := decodeB64(invalid, size); ok {
				t.Fatalf("accepted noncanonical %d-byte value %q", size, invalid)
			}
		}
	}
}

func TestControlMessageEncoding(t *testing.T) {
	id, token := strings.Repeat("a", 22), strings.Repeat("b", 43)
	for _, tc := range []struct {
		message controlMessage
		want    map[string]string
	}{
		{controlMessage{Type: "challenge", Nonce: token}, map[string]string{"type": "challenge", "nonce": token}},
		{controlMessage{Type: "registered", EndpointID: id}, map[string]string{"type": "registered", "endpointId": id}},
		{controlMessage{Type: "incoming", ConnectionID: id, Token: token}, map[string]string{"type": "incoming", "connectionId": id, "token": token}},
		{controlMessage{Type: "closed", ConnectionID: id}, map[string]string{"type": "closed", "connectionId": id}},
	} {
		t.Run(tc.message.Type, func(t *testing.T) {
			want, err := json.Marshal(tc.want)
			if err != nil {
				t.Fatal(err)
			}
			if got := textFrame(tc.message); string(got.data) != string(want) || got.typ != websocket.TextMessage {
				t.Fatalf("frame = %+v, want text %s", got, want)
			}
		})
	}
}

func TestControlQueueReusesClearedStorage(t *testing.T) {
	q := newQueue(maxQueueBytes, maxQueueMessages)
	f := frame{data: []byte("notification")}
	q.push(f)
	backing := &q.items[0]
	for range 100 {
		out, _, ok := q.next()
		if !ok || string(out.data) != string(f.data) {
			t.Fatal("lost notification")
		}
		if len(q.items) != 0 || cap(q.items) == 0 || backing.data != nil {
			t.Fatal("queue did not retain cleared storage")
		}
		q.release(out)
		if !q.push(f) || &q.items[0] != backing {
			t.Fatal("empty queue did not reuse storage")
		}
	}
	q.finish(closeMsg{code: 1001}, true)
	if q.items != nil || q.bytes != 0 || backing.data != nil {
		t.Fatal("finished queue retained a notification")
	}
}

func TestControlQueueKeepsInFlightBytesUntilWriteEnds(t *testing.T) {
	q := newQueue(8, 2)
	if !q.push(frame{data: []byte("1234")}) || !q.push(frame{data: []byte("5678")}) {
		t.Fatal("control queue rejected available capacity")
	}
	writing, _, ok := q.next()
	if !ok {
		t.Fatal("missing control message")
	}
	q.finish(closeMsg{code: 1001}, true)
	if q.bytes != 4 {
		t.Fatalf("held %d bytes, want the in-flight write", q.bytes)
	}
	q.release(writing)
	if q.bytes != 0 {
		t.Fatalf("write completed with %d bytes held", q.bytes)
	}
}

func TestHostNotificationsQueueOrCloseControl(t *testing.T) {
	for _, tc := range []struct {
		name      string
		gone      bool
		prepare   func(*queue)
		queued    bool
		closeWith string
	}{
		{name: "open queue", queued: true},
		{name: "full queue", prepare: func(q *queue) { q.push(textFrame(controlMessage{Type: "registered"})) }, closeWith: "control queue limit exceeded"},
		{name: "finished queue", prepare: func(q *queue) { q.finish(closeMsg{code: 1001, reason: "finished"}, true) }, closeWith: "finished"},
		{name: "host gone", gone: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := newQueue(1024, 1)
			h := &host{ctrl: &peer{q: q}, gone: tc.gone}
			if tc.prepare != nil {
				tc.prepare(q)
			}
			h.notify(controlMessage{Type: "incoming"})
			_, final, queued := q.next()
			if queued != tc.queued {
				t.Fatalf("notification queued=%v, want %v", queued, tc.queued)
			}
			reason := ""
			if final != nil {
				reason = final.reason
			}
			if reason != tc.closeWith {
				t.Fatalf("control close reason %q, want %q", reason, tc.closeWith)
			}
		})
	}
}
