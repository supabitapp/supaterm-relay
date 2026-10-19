package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestIdlePairedSocketsAnswerPings(t *testing.T) {
	for _, side := range []string{"client", "host"} {
		t.Run(side, func(t *testing.T) {
			r := startRelay(t)
			client, host, _ := pairUp(t, r, register(t, r))
			warm := message{websocket.BinaryMessage, []byte("ready")}
			send(t, client, warm)
			expectMessage(t, host, warm)
			send(t, host, warm)
			expectMessage(t, client, warm)

			target, other := client, host
			if side == "host" {
				target, other = host, client
			}
			pong := make(chan string, 1)
			target.SetPongHandler(func(data string) error {
				pong <- data
				return nil
			})
			_ = target.SetReadDeadline(time.Now().Add(deadline))
			read := make(chan error, 1)
			go func() {
				typ, data, err := target.ReadMessage()
				if err == nil && (typ != websocket.BinaryMessage || string(data) != "after pong") {
					err = fmt.Errorf("unexpected message: type=%d data=%q", typ, data)
				}
				read <- err
			}()
			if err := target.WriteControl(websocket.PingMessage, []byte("probe"), time.Now().Add(deadline)); err != nil {
				t.Fatal(err)
			}
			// The opposite source sends no application data until the pong arrives.
			// A buffered control reply must not depend on that source making progress.
			select {
			case data := <-pong:
				if data != "probe" {
					t.Fatalf("pong = %q", data)
				}
			case err := <-read:
				t.Fatalf("read ended before pong: %v", err)
			case <-time.After(deadline):
				t.Fatal("idle peer did not answer ping")
			}
			send(t, other, message{websocket.BinaryMessage, []byte("after pong")})
			select {
			case err := <-read:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(deadline):
				t.Fatal("data after pong did not arrive")
			}
		})
	}
}
