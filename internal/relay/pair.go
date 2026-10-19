package relay

import (
	"crypto/subtle"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/internal/admission"
)

type pairState int

const (
	pending pairState = iota
	accepting
	active
	closed
)

type pair struct {
	s         *Server
	id        string
	token     string
	host      *host
	state     pairState
	cause     closeMsg
	announced bool
	timer     *time.Timer
	ready     chan struct{}
	done      chan struct{}
	client    *peer
	clientKey netip.Addr
	hostPeer  *peer
	refs      int
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("endpointId")
	clientKey := admission.ClientKey(admission.ClientIP(r, s.cfg.TrustedProxies))
	s.mu.Lock()
	h := s.hosts[id]
	if h == nil {
		s.mu.Unlock()
		s.reject(w, http.StatusNotFound, "endpoint not found")
		return
	}
	if h.clientSlots >= s.cfg.MaxClientsPerHost {
		s.mu.Unlock()
		s.reject(w, http.StatusServiceUnavailable, "client capacity reached")
		return
	}
	if h.clientCounts[clientKey] >= s.cfg.MaxClientsPerHostPerIP {
		s.mu.Unlock()
		s.reject(w, http.StatusTooManyRequests, "client capacity for host reached")
		return
	}
	p := &pair{
		s:         s,
		refs:      1,
		id:        randomB64(16),
		token:     randomB64(32),
		host:      h,
		clientKey: clientKey,
		ready:     make(chan struct{}),
		done:      make(chan struct{}),
	}
	h.pairs[p.id] = p
	s.pairs[p.id] = p
	h.clientSlots++
	h.clientCounts[clientKey]++
	s.clientSlots++
	s.pending++
	p.timer = time.AfterFunc(s.cfg.PairTimeout, p.expire)
	s.mu.Unlock()
	defer p.releaseSlot()

	ws, ok := s.upgrade(w, r, int64(s.cfg.MaxMessageBytes))
	if !ok {
		p.close(closeMsg{websocket.CloseInternalServerErr, "upgrade failed"})
		return
	}
	cp := s.newPeer(ws, nil, &h.bytesOut)
	s.mu.Lock()
	if p.state == closed {
		cause := p.cause
		s.mu.Unlock()
		s.closeNow(ws, cause)
		return
	}
	p.client = cp
	p.announced = true
	h.notify(controlMessage{Type: "incoming", ConnectionID: p.id, Token: p.token})
	s.mu.Unlock()

	cp.readData(p)
}

func (s *Server) handleAccept(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	p := s.pairs[q.Get("connectionId")]
	if p != nil && p.host.id != q.Get("endpointId") {
		p = nil
	}
	if p == nil {
		s.mu.Unlock()
		s.reject(w, http.StatusNotFound, "connection not found")
		return
	}
	token := q.Get("token")
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(p.token)) != 1 || p.state != pending || p.client == nil {
		s.mu.Unlock()
		s.reject(w, http.StatusForbidden, "invalid token")
		return
	}
	p.state = accepting
	p.refs++
	s.mu.Unlock()
	defer p.releaseSlot()

	ws, ok := s.upgrade(w, r, int64(s.cfg.MaxMessageBytes))
	if !ok {
		p.close(closeMsg{websocket.CloseInternalServerErr, "host accept failed"})
		return
	}
	hp := s.newPeer(ws, nil, &p.host.bytesIn)
	s.mu.Lock()
	if p.state != accepting {
		cause := p.cause
		s.mu.Unlock()
		s.closeNow(ws, cause)
		return
	}
	p.state = active
	p.timer.Stop()
	p.hostPeer = hp
	s.pending--
	s.active++
	close(p.ready)
	s.mu.Unlock()

	hp.readData(p)
}

func (p *pair) expire() {
	p.closeWhen(closeMsg{websocket.CloseTryAgainLater, "pair timeout"}, true)
}

func (p *pair) close(c closeMsg) {
	p.closeWhen(c, false)
}

func (p *pair) closeWhen(c closeMsg, waitingOnly bool) {
	s := p.s
	s.mu.Lock()
	prev := p.state
	if waitingOnly && prev != pending && prev != accepting {
		s.mu.Unlock()
		return
	}
	if prev == closed {
		s.mu.Unlock()
		<-p.done
		return
	}
	p.state = closed
	p.cause = c
	h := p.host
	delete(h.pairs, p.id)
	delete(s.pairs, p.id)
	if prev == active {
		s.active--
	} else {
		s.pending--
	}
	if p.announced {
		h.notify(controlMessage{Type: "closed", ConnectionID: p.id})
	}
	client, hostPeer := p.client, p.hostPeer
	s.mu.Unlock()
	p.timer.Stop()
	// Close controls may run alongside a data writer. One shared deadline
	// bounds teardown even when either destination has stopped reading.
	deadline := time.Now().Add(closeGrace)
	var cleanup sync.WaitGroup
	for _, peer := range []*peer{client, hostPeer} {
		if peer == nil {
			continue
		}
		cleanup.Go(func() {
			_ = peer.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(c.code, c.reason), deadline)
			_ = peer.ws.Close()
		})
	}
	cleanup.Wait()
	close(p.done)
}

// Keep admission ownership until every accepted socket and writer has exited.
func (p *pair) releaseSlot() {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()
	p.refs--
	if p.refs > 0 {
		return
	}
	p.s.clientSlots--
	p.host.clientSlots--
	p.host.clientCounts[p.clientKey]--
	if p.host.clientCounts[p.clientKey] == 0 {
		delete(p.host.clientCounts, p.clientKey)
	}
}
