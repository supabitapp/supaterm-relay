package relay

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

type batchSinkConn struct {
	net.Conn
	writes int64
}

func (c *batchSinkConn) Write(b []byte) (int, error) {
	c.writes++
	return len(b), nil
}

func (*batchSinkConn) SetWriteDeadline(time.Time) error { return nil }

// This measures buffer overhead and socket-write count, not network throughput.
// The separate-process e2e benchmark measures the cost of real socket writes.
func BenchmarkBatchConnBurst(b *testing.B) {
	for _, size := range []int{64, 1024} {
		for _, frames := range []int{1, 4} {
			b.Run(fmt.Sprintf("%dB/%dframes", size, frames), func(b *testing.B) {
				header := 2
				if size >= 126 {
					header = 4
				}
				frame := make([]byte, header+size)
				frame[0] = 0x82
				frame[1] = byte(size)
				if header == 4 {
					frame[1] = 126
					binary.BigEndian.PutUint16(frame[2:], uint16(size))
				}
				conn := &batchSinkConn{}
				c := newBatchConn(conn)
				c.enable()
				b.SetBytes(int64(size * frames))
				b.ReportAllocs()
				for b.Loop() {
					for range frames {
						if _, err := c.Write(frame); err != nil {
							b.Fatal(err)
						}
					}
					if err := c.flush(); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(conn.writes)/float64(b.N*frames), "writes/frame")
			})
		}
	}
}
