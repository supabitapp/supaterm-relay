//go:build !linux

package main

import "errors"

type poller struct{}

func newPoller() (*poller, error) { return nil, errors.New("epoll requires linux") }
func (*poller) run()              {}
func (*poller) add(*conn) error   { return nil }
func (*poller) rearm(*conn) error { return nil }
func (*poller) remove(*conn)      {}
