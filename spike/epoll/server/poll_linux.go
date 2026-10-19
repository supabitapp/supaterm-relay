package main

import (
	"sync"

	"golang.org/x/sys/unix"
)

type poller struct {
	fd    int
	mu    sync.Mutex
	conns map[uint32]*conn
}

func newPoller() (*poller, error) {
	fd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &poller{fd: fd, conns: map[uint32]*conn{}}, nil
}

func (p *poller) ctl(op int, c *conn) error {
	ev := unix.EpollEvent{Events: unix.EPOLLIN | unix.EPOLLRDHUP | unix.EPOLLONESHOT, Fd: int32(c.id)}
	var err error
	ctlErr := c.raw.Control(func(fd uintptr) { err = unix.EpollCtl(p.fd, op, int(fd), &ev) })
	if ctlErr != nil {
		return ctlErr
	}
	return err
}

func (p *poller) add(c *conn) error {
	p.mu.Lock()
	p.conns[c.id] = c
	p.mu.Unlock()
	return p.ctl(unix.EPOLL_CTL_ADD, c)
}

func (p *poller) rearm(c *conn) error {
	return p.ctl(unix.EPOLL_CTL_MOD, c)
}

func (p *poller) remove(c *conn) {
	p.mu.Lock()
	_, ok := p.conns[c.id]
	delete(p.conns, c.id)
	p.mu.Unlock()
	if ok {
		_ = c.raw.Control(func(fd uintptr) { _ = unix.EpollCtl(p.fd, unix.EPOLL_CTL_DEL, int(fd), nil) })
	}
}

func (p *poller) run() {
	events := make([]unix.EpollEvent, 256)
	for {
		n, err := unix.EpollWait(p.fd, events, -1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			panic(err)
		}
		p.mu.Lock()
		for _, ev := range events[:n] {
			if c := p.conns[uint32(ev.Fd)]; c != nil {
				go c.wake()
			}
		}
		p.mu.Unlock()
	}
}
