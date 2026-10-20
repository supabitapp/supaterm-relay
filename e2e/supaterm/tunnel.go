package supaterm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"slices"
	"sync"
	"time"
)

const (
	frameOpen   = 1
	frameData   = 2
	frameWindow = 3
	frameFin    = 4
	frameRst    = 5
	framePing   = 6
	framePong   = 7

	headerBytes          = 9
	MaxPlainBytes        = 64 << 10
	MaxRecordBytes       = MaxPlainBytes + recordOverhead
	sessionWindow        = 8 << 20
	minMessageCost       = 48 << 10
	streamWindow         = 2 << 20
	streamSendQueueBytes = 8 << 20
	maxStreams           = 256
	keepaliveMisses      = 3
	maxWriteChunk        = 256 << 10
	KeepAlive            = 15 * time.Second
)

var (
	ErrStreamClosed = errors.New("tunnel stream closed")
	ErrStreamReset  = errors.New("tunnel stream reset")
	ErrTunnelClosed = errors.New("tunnel closed")
	ErrTimedOut     = errors.New("relay session timed out")
)

type SessionConfig struct {
	Cipher    *Cipher
	Send      func([]byte) error
	Initiator bool
	OnStream  func(*Stream)
	OnClose   func(error)
	KeepAlive time.Duration
}

type Session struct {
	mu        sync.Mutex
	wake      *sync.Cond
	cfg       SessionConfig
	streams   map[uint32]*Stream
	control   [][]byte
	ready     []*Stream
	scheduled bool
	closed    bool
	err       error
	done      chan struct{}

	sessionCredit        int
	sessionReceiveCredit int
	sessionGrant         int
	nextID               uint64
	lastRemoteID         uint64
	receivedSinceTick    bool
	idleTicks            int

	recordsReceived int64
	pongs           int64
}

func NewSession(cfg SessionConfig) *Session {
	if cfg.KeepAlive == 0 {
		cfg.KeepAlive = KeepAlive
	}
	s := &Session{
		cfg:                  cfg,
		streams:              map[uint32]*Stream{},
		done:                 make(chan struct{}),
		sessionCredit:        sessionWindow,
		sessionReceiveCredit: sessionWindow,
		nextID:               2,
	}
	if cfg.Initiator {
		s.nextID = 1
	}
	s.wake = sync.NewCond(&s.mu)
	go s.pump()
	go s.keepalive()
	return s
}

func frame(typ byte, id uint32, payload []byte) []byte {
	b := make([]byte, headerBytes+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint32(b[1:], id)
	binary.BigEndian.PutUint32(b[5:], uint32(len(payload)))
	copy(b[headerBytes:], payload)
	return b
}

func windowFrame(id uint32, n int) []byte {
	return frame(frameWindow, id, binary.BigEndian.AppendUint32(nil, uint32(n)))
}

func (s *Session) schedule() {
	if s.scheduled || s.closed {
		return
	}
	s.scheduled = true
	s.wake.Broadcast()
}

func (s *Session) markReady(st *Stream) {
	if !slices.Contains(s.ready, st) {
		s.ready = append(s.ready, st)
	}
	s.schedule()
}

func (s *Session) grantSession(n int) {
	if s.closed {
		return
	}
	s.sessionGrant += n
	if s.sessionGrant > 0 && (s.sessionGrant >= sessionWindow/4 || s.sessionReceiveCredit < sessionWindow/4) {
		s.control = append(s.control, windowFrame(0, s.sessionGrant))
		s.sessionReceiveCredit += s.sessionGrant
		s.sessionGrant = 0
		s.schedule()
	}
}

func (s *Session) finish(st *Stream, err error) {
	if st.closed {
		return
	}
	st.closed = true
	delete(s.streams, st.id)
	if i := slices.Index(s.ready, st); i >= 0 {
		s.ready = slices.Delete(s.ready, i, i+1)
	}
	failure := err
	if failure == nil {
		failure = ErrStreamClosed
	}
	for _, w := range st.pending {
		w.done(failure)
	}
	st.pending, st.pendingBytes = nil, 0
	s.grantSession(st.unconsumed)
	st.unconsumed = 0
	st.err = err
	st.cond.Broadcast()
}

func (s *Session) maybeFinish(st *Stream) {
	if st.finQueued && st.remoteEnded && len(st.pending) == 0 && st.unconsumed == 0 {
		s.finish(st, nil)
	}
}

func (s *Session) pump() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		for !s.closed && !s.scheduled {
			s.wake.Wait()
		}
		if s.closed {
			return
		}
		s.scheduled = false
		for !s.closed {
			plain, sent := s.nextRecord()
			if plain == nil {
				break
			}
			record := s.cfg.Cipher.Seal(plain)
			s.mu.Unlock()
			err := s.cfg.Send(record)
			s.mu.Lock()
			for _, done := range sent {
				done(err)
			}
			if err != nil {
				s.closeLocked(err)
				return
			}
			if s.sessionCredit < minMessageCost && len(s.control) == 0 {
				break
			}
		}
	}
}

func (s *Session) nextRecord() ([]byte, []func(error)) {
	var parts [][]byte
	var sent []func(error)
	size, data := 0, 0
	for len(s.control) > 0 && size+len(s.control[0]) <= MaxPlainBytes {
		parts = append(parts, s.control[0])
		size += len(s.control[0])
		s.control = s.control[1:]
	}
	for pass := len(s.ready); pass > 0 && size < MaxPlainBytes; pass-- {
		st := s.ready[0]
		s.ready = s.ready[1:]
		for len(st.pending) > 0 {
			head := st.pending[0]
			sessionRoom := 0
			if s.sessionCredit >= minMessageCost {
				sessionRoom = s.sessionCredit - data
			}
			room := min(MaxPlainBytes-size-headerBytes, st.sendCredit, sessionRoom)
			if room <= 0 {
				break
			}
			chunk := head.data[:min(room, len(head.data))]
			parts = append(parts, frame(frameData, st.id, chunk))
			size += headerBytes + len(chunk)
			data += len(chunk)
			st.pendingBytes -= len(chunk)
			st.sendCredit -= len(chunk)
			if len(chunk) == len(head.data) {
				st.pending = st.pending[1:]
				sent = append(sent, head.done)
			} else {
				head.data = head.data[len(chunk):]
			}
		}
		if len(st.pending) == 0 && st.localEnded && !st.finQueued && size+headerBytes <= MaxPlainBytes {
			st.finQueued = true
			parts = append(parts, frame(frameFin, st.id, nil))
			size += headerBytes
			s.maybeFinish(st)
		}
		if (len(st.pending) > 0 && st.sendCredit > 0) || (st.localEnded && !st.finQueued) {
			s.ready = append(s.ready, st)
		}
	}
	if len(parts) == 0 {
		return nil, nil
	}
	if data > 0 {
		s.sessionCredit -= max(data, minMessageCost)
	}
	return bytes.Join(parts, nil), sent
}

func (s *Session) keepalive() {
	tick := time.NewTicker(s.cfg.KeepAlive)
	defer tick.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
		}
		s.mu.Lock()
		switch {
		case s.receivedSinceTick:
			s.receivedSinceTick = false
			s.idleTicks = 0
		case s.idleTicks+1 >= keepaliveMisses:
			s.closeLocked(ErrTimedOut)
		default:
			s.idleTicks++
			s.control = append(s.control, frame(framePing, 0, nil))
			s.schedule()
		}
		s.mu.Unlock()
	}
}

type protocolError string

func (e protocolError) Error() string { return string(e) }

func (s *Session) Receive(record []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	plain, err := s.cfg.Cipher.Open(record, MaxPlainBytes)
	if err != nil {
		s.closeLocked(err)
		return
	}
	s.recordsReceived++
	if err := s.receive(plain); err != nil {
		s.closeLocked(err)
		return
	}
	if len(s.control) > maxStreams*4 {
		s.closeLocked(protocolError("tunnel control queue full"))
	}
}

func (s *Session) receive(plain []byte) error {
	data := 0
	for start := 0; start < len(plain); {
		if start+headerBytes > len(plain) {
			return protocolError("truncated tunnel frame")
		}
		length := int(binary.BigEndian.Uint32(plain[start+5:]))
		if start+headerBytes+length > len(plain) {
			return protocolError("truncated tunnel frame")
		}
		if plain[start] == frameData {
			data += length
		}
		start += headerBytes + length
	}
	s.receivedSinceTick = true
	if data > 0 {
		cost := max(data, minMessageCost)
		if cost > s.sessionReceiveCredit {
			return protocolError("tunnel session window exceeded")
		}
		s.sessionReceiveCredit -= cost
		s.grantSession(cost - data)
	}
	for offset := 0; offset < len(plain) && !s.closed; {
		typ := plain[offset]
		id := binary.BigEndian.Uint32(plain[offset+1:])
		length := int(binary.BigEndian.Uint32(plain[offset+5:]))
		payload := plain[offset+headerBytes : offset+headerBytes+length]
		offset += headerBytes + length
		if id != 0 && id%2 == 0 {
			return protocolError("invalid tunnel stream identifier")
		}
		switch typ {
		case frameWindow:
			if length != 4 {
				return protocolError("invalid tunnel window")
			}
			n := int(binary.BigEndian.Uint32(payload))
			if n == 0 {
				return protocolError("invalid tunnel window")
			}
			if id == 0 {
				s.sessionCredit += n
				if s.sessionCredit > sessionWindow {
					return protocolError("tunnel window overflow")
				}
				for _, st := range s.streams {
					if len(st.pending) > 0 || st.localEnded {
						s.markReady(st)
					}
				}
				continue
			}
			st := s.streams[id]
			if st == nil {
				continue
			}
			st.sendCredit += n
			if st.sendCredit > streamWindow {
				return protocolError("tunnel window overflow")
			}
			if len(st.pending) > 0 {
				s.markReady(st)
			}
			continue
		case framePing, framePong:
			if id != 0 || length != 0 {
				return protocolError("invalid tunnel keepalive")
			}
			if typ == framePing {
				s.control = append(s.control, frame(framePong, 0, nil))
				s.schedule()
			} else {
				s.pongs++
				s.wake.Broadcast()
			}
			continue
		case frameOpen:
			if length != 0 || s.cfg.Initiator || uint64(id) <= s.lastRemoteID || s.cfg.OnStream == nil {
				return protocolError("invalid tunnel open")
			}
			s.lastRemoteID = uint64(id)
			if len(s.streams) >= maxStreams {
				s.control = append(s.control, frame(frameRst, id, nil))
				s.schedule()
				continue
			}
			s.cfg.OnStream(s.newStream(id))
			continue
		}
		limit := s.nextID
		if !s.cfg.Initiator {
			limit = s.lastRemoteID + 2
		}
		if id == 0 || uint64(id) >= limit {
			return protocolError("unknown tunnel stream")
		}
		st := s.streams[id]
		switch typ {
		case frameData:
			if length == 0 {
				return protocolError("empty tunnel data")
			}
			if st == nil || st.remoteEnded {
				s.grantSession(length)
				continue
			}
			if length > st.receiveCredit {
				return protocolError("tunnel window exceeded")
			}
			st.receiveCredit -= length
			st.unconsumed += length
			st.inbox = append(st.inbox, bytes.Clone(payload))
			st.cond.Broadcast()
		case frameFin:
			if length != 0 {
				return protocolError("invalid tunnel FIN")
			}
			if st == nil || st.remoteEnded {
				continue
			}
			st.remoteEnded = true
			st.cond.Broadcast()
			s.maybeFinish(st)
		case frameRst:
			if length != 0 {
				return protocolError("invalid tunnel RST")
			}
			if st != nil {
				s.finish(st, ErrStreamReset)
			}
		default:
			return protocolError("unknown tunnel frame")
		}
	}
	return nil
}

func (s *Session) Open() (*Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closed:
		return nil, ErrTunnelClosed
	case !s.cfg.Initiator:
		return nil, errors.New("only the tunnel client can open streams")
	case len(s.streams) >= maxStreams:
		return nil, errors.New("too many tunnel streams")
	case s.nextID > 0xffff_ffff:
		return nil, errors.New("tunnel stream identifiers exhausted")
	}
	id := uint32(s.nextID)
	s.nextID += 2
	st := s.newStream(id)
	s.control = append(s.control, frame(frameOpen, id, nil))
	s.schedule()
	return st, nil
}

func (s *Session) Ping(timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	expired := time.AfterFunc(timeout, func() {
		s.mu.Lock()
		s.wake.Broadcast()
		s.mu.Unlock()
	})
	defer expired.Stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrTunnelClosed
	}
	want := s.pongs + 1
	s.control = append(s.control, frame(framePing, 0, nil))
	s.schedule()
	for s.pongs < want {
		switch {
		case s.closed:
			return 0, ErrTunnelClosed
		case time.Since(start) >= timeout:
			return 0, os.ErrDeadlineExceeded
		}
		s.wake.Wait()
	}
	return time.Since(start), nil
}

func (s *Session) Close(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked(err)
}

func (s *Session) closeLocked(err error) {
	if s.closed {
		return
	}
	s.closed = true
	s.err = err
	close(s.done)
	s.control, s.ready = nil, nil
	failure := err
	if failure == nil {
		failure = ErrTunnelClosed
	}
	for _, st := range s.streams {
		s.finish(st, failure)
	}
	s.wake.Broadcast()
	if s.cfg.OnClose != nil {
		go s.cfg.OnClose(err)
	}
}

func (s *Session) Done() <-chan struct{} { return s.done }

func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Session) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Session) StreamCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

func (s *Session) RecordsReceived() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recordsReceived
}

type pendingWrite struct {
	data []byte
	done func(error)
}

type Stream struct {
	s    *Session
	id   uint32
	cond *sync.Cond

	pending       []*pendingWrite
	pendingBytes  int
	unconsumed    int
	sendCredit    int
	receiveCredit int
	receiveGrant  int
	localEnded    bool
	finQueued     bool
	remoteEnded   bool
	closed        bool
	err           error
	inbox         [][]byte

	readDeadline  time.Time
	writeDeadline time.Time
	readTimer     *time.Timer
	writeTimer    *time.Timer
}

func (s *Session) newStream(id uint32) *Stream {
	st := &Stream{s: s, id: id, cond: sync.NewCond(&s.mu), sendCredit: streamWindow, receiveCredit: streamWindow}
	s.streams[id] = st
	return st
}

func (st *Stream) ID() uint32 { return st.id }

func (st *Stream) write(data []byte, done func(error)) error {
	if st.closed || st.localEnded {
		return ErrStreamClosed
	}
	if len(data) == 0 {
		done(nil)
		return nil
	}
	if st.pendingBytes+len(data) > streamSendQueueBytes {
		return errors.New("tunnel stream send queue full")
	}
	st.pendingBytes += len(data)
	st.pending = append(st.pending, &pendingWrite{data: data, done: done})
	if st.sendCredit > 0 {
		st.s.markReady(st)
	}
	return nil
}

func (st *Stream) consumed(n int) {
	if st.closed {
		return
	}
	s := st.s
	st.unconsumed -= n
	s.grantSession(n)
	st.receiveGrant += n
	if st.receiveGrant >= streamWindow/4 {
		s.control = append(s.control, windowFrame(st.id, st.receiveGrant))
		st.receiveCredit += st.receiveGrant
		st.receiveGrant = 0
		s.schedule()
	}
	s.maybeFinish(st)
}

func (st *Stream) reset() {
	if st.closed {
		return
	}
	s := st.s
	s.control = append(s.control, frame(frameRst, st.id, nil))
	s.schedule()
	s.finish(st, nil)
}
