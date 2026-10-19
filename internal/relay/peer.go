package relay

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

type peer struct {
	s            *Server
	ws           *websocket.Conn
	q            *queue
	traffic      *atomic.Int64
	writeTimeout time.Duration
	dead         chan struct{}
	cause        atomic.Pointer[closeMsg]
	pingMu       sync.Mutex
	pinger       *time.Timer
}

func (s *Server) newPeer(ws *websocket.Conn, q *queue, traffic *atomic.Int64) *peer {
	p := &peer{s: s, ws: ws, q: q, traffic: traffic, writeTimeout: writeTimeout, dead: make(chan struct{})}
	if traffic != nil {
		p.writeTimeout = s.cfg.DeliveryTimeout
	}
	p.extend()
	ws.SetPongHandler(func(string) error {
		p.extend()
		return nil
	})
	return p
}

func (p *peer) extend() {
	_ = p.ws.SetReadDeadline(time.Now().Add(p.s.cfg.pongTimeout()))
}

func (p *peer) fail(c closeMsg) {
	p.cause.CompareAndSwap(nil, &c)
	_ = p.ws.Close()
}

func (p *peer) exit() {
	if p.q != nil {
		p.q.finish(closeMsg{websocket.CloseGoingAway, "peer disconnected"}, true)
	}
	close(p.dead)
}

func (p *peer) ping() bool {
	if err := p.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(p.writeTimeout)); err != nil {
		p.fail(closeMsg{websocket.CloseGoingAway, "peer unreachable"})
		return false
	}
	return true
}

func (p *peer) writeLoop() {
	defer p.q.finish(closeMsg{websocket.CloseGoingAway, "writer stopped"}, true)
	defer p.s.forget(p.ws)
	ticker := time.NewTicker(p.s.cfg.Heartbeat)
	defer ticker.Stop()
	for {
		f, final, ok := p.q.next()
		if ok {
			_ = p.ws.SetWriteDeadline(time.Now().Add(p.writeTimeout))
			err := p.ws.WriteMessage(f.typ, f.data)
			p.q.release(f)
			if err != nil {
				p.fail(closeMsg{websocket.CloseTryAgainLater, "peer write timeout"})
				return
			}
			if p.traffic != nil {
				p.s.forwardedMessages.Add(1)
				p.s.forwardedBytes.Add(int64(len(f.data)))
				p.traffic.Add(int64(len(f.data)))
			}
			select {
			case <-ticker.C:
				if !p.ping() {
					return
				}
			default:
			}
			continue
		}
		if final != nil {
			_ = p.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(final.code, final.reason), time.Now().Add(writeTimeout))
			_ = p.ws.SetReadDeadline(time.Now().Add(closeGrace))
			return
		}
		select {
		case <-p.q.wake:
		case <-ticker.C:
			if !p.ping() {
				return
			}
		case <-p.dead:
			return
		}
	}
}

func (p *peer) readControl() {
	defer p.exit()
	for {
		if _, _, err := p.ws.ReadMessage(); err != nil {
			return
		}
		p.q.finish(closeMsg{websocket.ClosePolicyViolation, "unexpected control message"}, true)
	}
}

// Each data direction reads directly into the destination's fixed WebSocket
// writer buffer. A stalled writer stops its source; no payload queue is kept.
func (p *peer) readData(pr *pair) {
	defer p.s.forget(p.ws)
	defer p.stopPings()
	defer p.exit()
	p.startPings()
	select {
	case <-pr.ready:
	case <-pr.done:
		return
	}
	p.s.mu.Lock()
	out := pr.hostPeer
	if p == pr.hostPeer {
		out = pr.client
	}
	p.s.mu.Unlock()
	progress := &progressReader{peer: p}
	for {
		typ, reader, err := p.ws.NextReader()
		if err != nil {
			pr.close(p.closeCause(err))
			return
		}
		_ = out.ws.SetWriteDeadline(time.Now().Add(p.s.cfg.DeliveryTimeout))
		writer, err := out.ws.NextWriter(typ)
		if err != nil {
			pr.close(closeMsg{websocket.CloseTryAgainLater, "peer write timeout"})
			return
		}
		progress.reader, progress.err, progress.out = reader, nil, out
		n, err := io.Copy(writer, progress)
		if err != nil {
			// Closing the message writer here would turn a truncated input into
			// a valid shorter message. Close the pair with the fragment unfinished.
			cause := closeMsg{websocket.CloseTryAgainLater, "peer write timeout"}
			if progress.err != nil {
				cause = p.closeCause(progress.err)
			}
			pr.close(cause)
			return
		}
		if err := writer.Close(); err != nil {
			pr.close(closeMsg{websocket.CloseTryAgainLater, "peer write timeout"})
			return
		}
		p.s.forwardedMessages.Add(1)
		p.s.forwardedBytes.Add(n)
		out.traffic.Add(n)
		p.extend()
	}
}

type progressReader struct {
	reader io.Reader
	peer   *peer
	out    *peer
	err    error
}

func (r *progressReader) Read(b []byte) (int, error) {
	n, err := r.reader.Read(b)
	if n > 0 {
		r.peer.extend()
		_ = r.out.ws.SetWriteDeadline(time.Now().Add(r.peer.s.cfg.DeliveryTimeout))
	}
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}

func (p *peer) startPings() {
	p.pingMu.Lock()
	p.pinger = time.AfterFunc(p.s.cfg.Heartbeat, p.tick)
	p.pingMu.Unlock()
}

func (p *peer) tick() {
	p.pingMu.Lock()
	defer p.pingMu.Unlock()
	select {
	case <-p.dead:
		return
	default:
	}
	if p.ping() {
		p.pinger.Reset(p.s.cfg.Heartbeat)
	}
}

// stopPings runs after exit and waits for a ping in progress, so no write
// outlives the socket.
func (p *peer) stopPings() {
	p.pingMu.Lock()
	p.pinger.Stop()
	p.pingMu.Unlock()
}

func (p *peer) closeCause(err error) closeMsg {
	if c := p.cause.Load(); c != nil {
		return *c
	}
	var ce *websocket.CloseError
	switch {
	case errors.As(err, &ce) && ce.Code == websocket.CloseNoStatusReceived:
		return closeMsg{websocket.CloseNormalClosure, ""}
	case errors.As(err, &ce) && sendableCode(ce.Code):
		return closeMsg{ce.Code, ce.Text}
	case errors.Is(err, websocket.ErrReadLimit):
		return closeMsg{websocket.CloseMessageTooBig, "message too big"}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return closeMsg{websocket.CloseGoingAway, "peer timeout"}
	}
	return closeMsg{websocket.CloseGoingAway, "peer disconnected"}
}

func sendableCode(c int) bool {
	return (c >= 1000 && c <= 1003) || (c >= 1007 && c <= 1014) || (c >= 3000 && c <= 4999)
}
