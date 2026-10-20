package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/supabitapp/supaterm-relay/e2e/supaterm"
	"github.com/supabitapp/supaterm-relay/internal/endpoint"
)

func main() {
	mode := flag.String("mode", "http", "http, control, connect, smoke, or tunnel")
	target := flag.String("url", "", "URL for http mode, ws base for control and connect")
	n := flag.Int("n", 1, "attempts")
	xff := flag.String("xff", "", "spoofed X-Forwarded-For, X-Real-IP, and Forwarded value")
	endpointID := flag.String("endpoint", strings.Repeat("ab", 32), "endpoint id for connect mode")
	flag.Parse()

	out := map[string]any{"mode": *mode}
	switch *mode {
	case "tunnel":
		rounds, err := tunnel(*target, *n)
		out["roundsVerified"] = rounds
		if err != nil {
			out["error"] = err.Error()
			_ = json.NewEncoder(os.Stdout).Encode(out)
			os.Exit(1)
		}
	case "smoke":
		pairs, err := smoke(*target, *n)
		out["pairsVerified"] = pairs
		if err != nil {
			out["error"] = err.Error()
			_ = json.NewEncoder(os.Stdout).Encode(out)
			os.Exit(1)
		}
	case "http":
		c := http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get(*target)
		if err != nil {
			out["error"] = err.Error()
			break
		}
		resp.Body.Close()
		out["status"] = resp.StatusCode
	default:
		hdr := http.Header{}
		if *xff != "" {
			hdr.Set("X-Forwarded-For", *xff)
			hdr.Set("X-Real-IP", *xff)
			hdr.Set("Forwarded", "for="+*xff)
		}
		var codes []int
		for range *n {
			url := *target + "/v1/connect?endpointId=" + *endpointID
			if *mode == "control" {
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				url = *target + "/v1/control?publicKey=" + endpoint.B64(pub)
			}
			ws, resp, err := endpoint.Dialer.Dial(url, hdr)
			switch {
			case err == nil:
				ws.Close()
				codes = append(codes, 101)
			case resp != nil:
				codes = append(codes, resp.StatusCode)
			default:
				codes = append(codes, 0)
			}
		}
		out["codes"] = codes
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}

func smoke(base string, hosts int) (int, error) {
	verified := 0
	if hosts <= 0 {
		return 0, errors.New("host count must be positive")
	}
	for i := range hosts {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		h, err := endpoint.Register(base, priv)
		if err != nil {
			return verified, fmt.Errorf("host %d register: %w", i, err)
		}
		err = smokePair(base, h)
		h.Close()
		if err != nil {
			return verified, fmt.Errorf("host %d: %w", i, err)
		}
		verified++
	}
	return verified, nil
}

func smokePair(base string, h *endpoint.Host) error {
	client, resp, err := endpoint.Connect(base, h.ID)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("connect: HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Close()
	ev, err := h.Next(10 * time.Second)
	if err != nil || ev.Type != "incoming" {
		return fmt.Errorf("no incoming event: %v", err)
	}
	accepted, resp, err := h.Accept(ev)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("accept: HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("accept: %w", err)
	}
	defer accepted.Close()
	for k := range 20 {
		typ, payload := websocket.TextMessage, []byte(fmt.Sprintf("smoke-%d", k))
		if k%2 == 1 {
			typ, payload = websocket.BinaryMessage, make([]byte, 1024+k)
			_, _ = rand.Read(payload)
		}
		from, to := client, accepted
		if k%3 == 2 {
			from, to = accepted, client
		}
		_ = from.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := from.WriteMessage(typ, payload); err != nil {
			return fmt.Errorf("write %d: %w", k, err)
		}
		_ = to.SetReadDeadline(time.Now().Add(10 * time.Second))
		gotTyp, got, err := to.ReadMessage()
		if err != nil {
			return fmt.Errorf("read %d: %w", k, err)
		}
		if gotTyp != typ || !bytes.Equal(got, payload) {
			return errors.New("payload mismatch")
		}
	}
	return nil
}

func tunnel(base string, rounds int) (int, error) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	h := supaterm.StartHost(supaterm.HostConfig{Identity: priv, RelayURL: base})
	defer h.Stop()
	srv := &http.Server{Handler: supaterm.FixtureHandler("smoke")}
	go func() { _ = srv.Serve(h) }()
	defer srv.Close()
	if !h.WaitStatus(supaterm.StatusRegistered, 15*time.Second) {
		return 0, fmt.Errorf("host did not register: %v %v", h.Statuses(), h.Violations())
	}
	c := supaterm.NewConnector(supaterm.ClientConfig{RelayURL: base, Address: h.Address()})
	defer c.Close()
	client := c.HTTPClient()
	client.Timeout = 30 * time.Second
	verified := 0
	for i := range rounds {
		size := 1<<20 + i
		resp, err := client.Get(fmt.Sprintf("http://supaterm.test/api/test/bytes/%d", size))
		if err != nil {
			return verified, fmt.Errorf("round %d: %w", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || !bytes.Equal(body, supaterm.Pattern(0, size)) {
			return verified, fmt.Errorf("round %d: %d bytes, %v", i, len(body), err)
		}
		verified++
	}
	ws, _, err := (&websocket.Dialer{NetDialContext: c.DialContext}).Dial("ws://supaterm.test/ws", nil)
	if err != nil {
		return verified, fmt.Errorf("inner websocket: %w", err)
	}
	defer ws.Close()
	payload := make([]byte, 64<<10)
	_, _ = rand.Read(payload)
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := ws.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		return verified, err
	}
	if _, got, err := ws.ReadMessage(); err != nil || !bytes.Equal(got, payload) {
		return verified, fmt.Errorf("inner websocket echo: %v", err)
	}
	s, err := c.Session(context.Background())
	if err != nil {
		return verified, err
	}
	if _, err := s.Ping(2 * time.Second); err != nil {
		return verified, fmt.Errorf("encrypted probe: %w", err)
	}
	if v := h.Violations(); len(v) > 0 {
		return verified, fmt.Errorf("relay protocol violations: %q", v)
	}
	return verified, nil
}
