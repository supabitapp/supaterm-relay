package relay

import (
	"sync"
)

type frame struct {
	typ  int
	data []byte
}

type closeMsg struct {
	code   int
	reason string
}

type queue struct {
	mu       sync.Mutex
	items    []frame
	bytes    int
	maxBytes int
	maxMsgs  int
	final    *closeMsg
	wake     chan struct{}
}

func newQueue(maxBytes, maxMsgs int) *queue {
	return &queue{maxBytes: maxBytes, maxMsgs: maxMsgs, wake: make(chan struct{}, 1)}
}

func (q *queue) push(f frame) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.final != nil {
		return true
	}
	if len(q.items) >= q.maxMsgs || len(f.data) > q.maxBytes-q.bytes {
		return false
	}
	q.items = append(q.items, f)
	q.bytes += len(f.data)
	q.signal()
	return true
}

func (q *queue) finish(c closeMsg, discard bool) {
	q.mu.Lock()
	if q.final == nil {
		q.final = &c
	}
	if discard {
		for _, frame := range q.items {
			q.bytes -= len(frame.data)
		}
		clear(q.items)
		q.items = nil
	}
	q.mu.Unlock()
	q.signal()
}

func (q *queue) next() (frame, *closeMsg, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return frame{}, q.final, false
	}
	f := q.items[0]
	q.items[0] = frame{}
	if len(q.items) == 1 {
		// Reuse the empty queue for the next notification instead of allocating
		// a new backing array on every push/pop in the common unqueued case.
		q.items = q.items[:0]
	} else {
		q.items = q.items[1:]
	}
	return f, nil, true
}

func (q *queue) release(f frame) {
	q.mu.Lock()
	q.bytes -= len(f.data)
	q.mu.Unlock()
}

func (q *queue) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}
