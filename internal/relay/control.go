package relay

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var signaturePrefixes = []string{"supaterm-relay-v1\n", "supacode-relay-v1\n"}

const (
	controlReadLimit = 4096
	closeSuperseded  = 4001
	maxQueueBytes    = 64 << 10
	maxQueueMessages = 256
)

type controlMessage struct {
	ConnectionID string `json:"connectionId,omitempty"`
	EndpointID   string `json:"endpointId,omitempty"`
	Nonce        string `json:"nonce,omitempty"`
	Token        string `json:"token,omitempty"`
	Type         string `json:"type"`
}

type host struct {
	id           string
	ctrl         *peer
	pairs        map[string]*pair
	clientSlots  int
	clientCounts map[netip.Addr]int
	gone         bool
	bytesIn      atomic.Int64
	bytesOut     atomic.Int64
}

func (h *host) notify(v controlMessage) {
	if !h.gone && !h.ctrl.q.push(textFrame(v)) {
		h.ctrl.q.finish(closeMsg{websocket.CloseTryAgainLater, "control queue limit exceeded"}, true)
	}
}

func (s *Server) handleControl(w http.ResponseWriter, r *http.Request) func() {
	pub, ok := decodeB64(r.URL.Query().Get("publicKey"), ed25519.PublicKeySize)
	if !ok {
		s.reject(w, http.StatusBadRequest, "invalid publicKey")
		return nil
	}
	ws, ok := s.upgrade(w, r, controlReadLimit)
	if !ok {
		return nil
	}
	id := endpointID(pub)
	nonce := randomB64(32)
	challenge := textFrame(controlMessage{Type: "challenge", Nonce: nonce})
	_ = ws.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := ws.WriteMessage(challenge.typ, challenge.data); err != nil {
		s.forget(ws)
		return nil
	}
	_ = ws.SetReadDeadline(time.Now().Add(s.cfg.AuthTimeout))
	if !verifyAuth(ws, pub, id+"\n"+nonce) {
		s.countRejection("authentication failed")
		s.closeNow(ws, closeMsg{websocket.ClosePolicyViolation, "authentication failed"})
		return nil
	}

	ctrl := s.newPeer(ws, newQueue(maxQueueBytes, maxQueueMessages), nil)
	h := &host{id: id, ctrl: ctrl, pairs: map[string]*pair{}, clientCounts: map[netip.Addr]int{}}
	ctrl.q.push(textFrame(controlMessage{Type: "registered", EndpointID: id}))
	s.mu.Lock()
	if s.draining.Load() {
		s.mu.Unlock()
		s.closeNow(ws, closeMsg{websocket.CloseGoingAway, "relay draining"})
		return nil
	}
	old := s.hosts[id]
	s.hosts[id] = h
	s.mu.Unlock()
	if old != nil {
		s.superseded.Add(1)
		old.ctrl.q.finish(closeMsg{closeSuperseded, "registration superseded"}, true)
	}

	return func() {
		var writer sync.WaitGroup
		writer.Go(ctrl.writeLoop)
		defer writer.Wait()
		ctrl.readControl()
		s.removeHost(h)
	}
}

func verifyAuth(ws *websocket.Conn, pub ed25519.PublicKey, challenge string) bool {
	typ, data, err := ws.ReadMessage()
	if err != nil || typ != websocket.TextMessage {
		return false
	}
	var auth struct {
		Type      string `json:"type"`
		Signature string `json:"signature"`
	}
	if json.Unmarshal(data, &auth) != nil || auth.Type != "authenticate" {
		return false
	}
	sig, ok := decodeB64(auth.Signature, ed25519.SignatureSize)
	if !ok {
		return false
	}
	for _, prefix := range signaturePrefixes {
		if ed25519.Verify(pub, []byte(prefix+challenge), sig) {
			return true
		}
	}
	return false
}

func (s *Server) removeHost(h *host) {
	s.mu.Lock()
	if s.hosts[h.id] == h {
		delete(s.hosts, h.id)
	}
	h.gone = true
	pairs := make([]*pair, 0, len(h.pairs))
	for _, p := range h.pairs {
		pairs = append(pairs, p)
	}
	s.mu.Unlock()
	var cleanup sync.WaitGroup
	for _, p := range pairs {
		cleanup.Go(func() {
			p.close(closeMsg{websocket.CloseGoingAway, "host offline"})
		})
	}
	cleanup.Wait()
}

func decodeB64(s string, n int) ([]byte, bool) {
	// Strict decoding checks trailing bits; exact encoded and decoded lengths
	// also rule out the CR/LF bytes that the decoder otherwise ignores.
	if len(s) != base64.RawURLEncoding.EncodedLen(n) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != n {
		return nil, false
	}
	return b, true
}

func endpointID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}
