//go:build unix

package relay

import (
	"io"
	"net"
	"os"
	"syscall"
)

func rawConn(conn net.Conn) syscall.RawConn {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return nil
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return nil
	}
	return raw
}

// fill takes a pooled buffer only for a read that completes without waiting,
// so a reader blocked on an idle socket holds no extra memory.
func (c *batchConn) fill() error {
	var n int
	var readErr error
	err := c.raw.Read(func(fd uintptr) bool {
		buf := readBuffers.Get().(*[readBatchSize]byte)
		for {
			n, readErr = syscall.Read(int(fd), buf[:])
			if readErr != syscall.EINTR {
				break
			}
		}
		if n > 0 {
			c.readBuf, c.unread = buf, buf[:n]
		} else {
			readBuffers.Put(buf)
		}
		return readErr != syscall.EAGAIN
	})
	switch {
	case err != nil:
		return err
	case readErr != nil:
		return &net.OpError{Op: "read", Net: c.LocalAddr().Network(), Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: os.NewSyscallError("read", readErr)}
	case n == 0:
		return io.EOF
	}
	return nil
}
