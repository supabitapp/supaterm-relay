package supaterm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const uploadBytes = 20 << 20

type Fixture struct {
	HTTP        *http.Client
	Origin      string
	Dial        func(ctx context.Context, network, addr string) (net.Conn, error)
	Environment string
}

type Check struct {
	Name string
	Run  func() error
}

func (f Fixture) Checks() []Check {
	return []Check{
		{"environment", f.environment},
		{"auth", f.auth},
		{"site", f.site},
		{"mjpeg", f.mjpeg},
		{"upload", f.upload},
		{"video", f.video},
		{"range", f.rangeRequest},
		{"websockets", f.websockets},
	}
}

func (f Fixture) do(method, path string, body io.Reader, header ...string) (*http.Response, []byte, error) {
	req, err := http.NewRequest(method, f.Origin+path, body)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp, data, err
}

func (f Fixture) expect(status int, method, path string, body io.Reader, header ...string) (*http.Response, []byte, error) {
	resp, data, err := f.do(method, path, body, header...)
	if err == nil && resp.StatusCode != status {
		err = fmt.Errorf("%s %s: %s %q (relay error %q)", method, path, resp.Status, data, resp.Header.Get("X-Supaterm-Relay-Error"))
	}
	return resp, data, err
}

func (f Fixture) getOK(path string, header ...string) ([]byte, error) {
	_, data, err := f.expect(http.StatusOK, http.MethodGet, path, nil, header...)
	return data, err
}

func (f Fixture) environment() error {
	data, err := f.getOK("/.well-known/supaterm/environment")
	if err != nil {
		return err
	}
	var env struct{ EnvironmentID string }
	if err := json.Unmarshal(data, &env); err != nil {
		return err
	}
	if env.EnvironmentID != f.Environment {
		return fmt.Errorf("reached environment %q, want %q", env.EnvironmentID, f.Environment)
	}
	return nil
}

func (f Fixture) token(subject string, status int) ([]byte, error) {
	form := strings.NewReader(url.Values{"subject_token": {subject}}.Encode())
	_, data, err := f.expect(status, http.MethodPost, "/oauth/token", form, "Content-Type", "application/x-www-form-urlencoded")
	return data, err
}

func (f Fixture) auth() error {
	if _, err := f.token("wrong", http.StatusUnauthorized); err != nil {
		return err
	}
	data, err := f.token(FixtureBootstrap, http.StatusOK)
	if err != nil {
		return err
	}
	var grant struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &grant); err != nil || grant.AccessToken == "" {
		return fmt.Errorf("token grant %q: %v", data, err)
	}
	if _, _, err := f.expect(http.StatusUnauthorized, http.MethodGet, "/api/auth/session", nil); err != nil {
		return err
	}
	bearer := []string{"Authorization", "Bearer " + grant.AccessToken}
	if data, err = f.getOK("/api/auth/session", bearer...); err != nil {
		return err
	}
	var session struct {
		Authenticated bool
		RemoteAddress string
	}
	if err := json.Unmarshal(data, &session); err != nil || !session.Authenticated || session.RemoteAddress != "relay" {
		return fmt.Errorf("session %q: %v", data, err)
	}
	if data, err = f.getOK("/api/auth/websocket-ticket", bearer...); err != nil {
		return err
	}
	if !bytes.Contains(data, []byte("fixture-ticket")) {
		return fmt.Errorf("ticket %q", data)
	}
	return nil
}

func (f Fixture) site() error {
	resp, html, err := f.expect(http.StatusOK, http.MethodGet, "/api/test/site/index.html", nil)
	if err != nil {
		return err
	}
	if resp.Header.Get("Content-Security-Policy") == "" || !bytes.Contains(html, []byte(`src="app.js"`)) {
		return fmt.Errorf("html %q with policy %q", html, resp.Header.Get("Content-Security-Policy"))
	}
	for path, want := range map[string]func([]byte) bool{
		"/api/test/site/style.css":    func(b []byte) bool { return string(b) == "body{width:123px}" },
		"/api/test/site/app.js":       func(b []byte) bool { return bytes.Contains(b, []byte("script ran")) },
		"/api/test/image.png":         func(b []byte) bool { return bytes.Equal(b, PNG) },
		"/api/test/site/img/logo.png": func(b []byte) bool { return bytes.Equal(b, PNG) },
	} {
		data, err := f.getOK(path)
		if err != nil {
			return err
		}
		if !want(data) {
			return fmt.Errorf("%s returned %q", path, data)
		}
	}
	_, _, err = f.expect(http.StatusNotFound, http.MethodGet, "/not-relayed", nil)
	return err
}

func (f Fixture) mjpeg() error {
	data, err := f.getOK("/api/test/stream.mjpeg")
	if err != nil {
		return err
	}
	if frames := bytes.Count(data, []byte("--frame")); frames != MJPEGFrames {
		return fmt.Errorf("%d frames", frames)
	}
	return nil
}

func (f Fixture) upload() error {
	body := make([]byte, uploadBytes)
	_, _ = rand.Read(body)
	_, data, err := f.expect(http.StatusOK, http.MethodPost, "/api/test/upload", bytes.NewReader(body))
	if err == nil && string(data) != strconv.Itoa(uploadBytes) {
		err = fmt.Errorf("host counted %s of %d uploaded bytes", data, uploadBytes)
	}
	return err
}

func (f Fixture) video() error {
	data, err := f.getOK("/api/test/video")
	if err == nil && (len(data) != VideoBytes || bytes.Count(data, []byte{7}) != VideoBytes) {
		err = fmt.Errorf("video of %d bytes differs", len(data))
	}
	return err
}

func (f Fixture) rangeRequest() error {
	resp, data, err := f.expect(http.StatusPartialContent, http.MethodGet, "/api/test/video", nil, "Range", "bytes=1000-2999999")
	if err != nil {
		return err
	}
	if want := fmt.Sprintf("bytes 1000-2999999/%d", VideoBytes); resp.Header.Get("Content-Range") != want {
		return fmt.Errorf("content range %q, want %q", resp.Header.Get("Content-Range"), want)
	}
	if len(data) != 2_999_000 || bytes.Count(data, []byte{7}) != len(data) {
		return fmt.Errorf("range of %d bytes differs", len(data))
	}
	return nil
}

func (f Fixture) websockets() error {
	dialer := websocket.Dialer{NetDialContext: f.Dial, HandshakeTimeout: 30 * time.Second}
	base := "ws" + strings.TrimPrefix(f.Origin, "http")
	for _, path := range []string{"/ws", "/api/device-hub/devices"} {
		if err := echo(dialer, base+path); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	if ws, _, err := dialer.Dial(base+"/api/other", nil); err == nil {
		ws.Close()
		return errors.New("host upgraded an unknown path")
	}
	return nil
}

type wsMessage struct {
	typ  int
	data []byte
}

func echo(dialer websocket.Dialer, url string) error {
	ws, _, err := dialer.Dial(url, nil)
	if err != nil {
		return err
	}
	defer ws.Close()
	var sent []wsMessage
	for i, n := range []int{0, 1, 125, 126, 65535, 65536, 1 << 20, 3 << 20} {
		m := wsMessage{websocket.TextMessage, bytes.Repeat([]byte("x"), n)}
		if i%2 == 1 {
			m = wsMessage{websocket.BinaryMessage, make([]byte, n)}
			_, _ = rand.Read(m.data)
		}
		sent = append(sent, m)
	}
	for i := range 200 {
		sent = append(sent, wsMessage{websocket.TextMessage, fmt.Appendf(nil, "ping %d", i)})
	}
	go func() {
		for _, m := range sent {
			if ws.WriteMessage(m.typ, m.data) != nil {
				return
			}
		}
	}()
	for i, want := range sent {
		_ = ws.SetReadDeadline(time.Now().Add(30 * time.Second))
		typ, data, err := ws.ReadMessage()
		if err != nil {
			return fmt.Errorf("message %d: %w", i, err)
		}
		if typ != want.typ || !bytes.Equal(data, want.data) {
			return fmt.Errorf("message %d echoed as type %d with %d bytes, sent type %d with %d", i, typ, len(data), want.typ, len(want.data))
		}
	}
	return nil
}
