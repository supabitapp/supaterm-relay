//go:build !unix

package relay

import (
	"errors"
	"net"
	"syscall"
)

func rawConn(net.Conn) syscall.RawConn { return nil }

func (*batchConn) fill() error { return errors.ErrUnsupported }
