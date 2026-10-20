package supaterm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	FixtureBootstrap = "fixture-bootstrap"
	fixtureBearer    = "fixture-bearer"
	VideoBytes       = 20 << 20
	MJPEGFrames      = 10
)

var (
	PNG, _ = base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jfWQAAAAASUVORK5CYII=")
	ranges = regexp.MustCompile(`^bytes=(\d+)-(\d+)$`)
)

func Pattern(offset, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((offset + i) % 251)
	}
	return b
}

func relayPath(p string) bool {
	return p == "/ws" || strings.HasPrefix(p, "/api/") || p == "/oauth/token" || p == "/.well-known/supaterm/environment"
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func FixtureHandler(environmentID string) http.Handler {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		p := r.URL.Path
		if !relayPath(p) {
			http.NotFound(w, r)
			return
		}
		if websocket.IsWebSocketUpgrade(r) {
			if p != "/ws" && !strings.HasPrefix(p, "/api/device-hub/") {
				http.NotFound(w, r)
				return
			}
			ws, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer ws.Close()
			for {
				typ, data, err := ws.ReadMessage()
				if err != nil {
					return
				}
				if err := ws.WriteMessage(typ, data); err != nil {
					return
				}
			}
		}
		switch {
		case p == "/.well-known/supaterm/environment":
			writeJSON(w, map[string]string{"environmentId": environmentID})
		case p == "/oauth/token":
			if r.ParseForm() != nil || r.PostForm.Get("subject_token") != FixtureBootstrap {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			writeJSON(w, map[string]string{"access_token": fixtureBearer})
		case strings.HasPrefix(p, "/api/auth/"):
			if r.Header.Get("Authorization") != "Bearer "+fixtureBearer {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if strings.HasSuffix(p, "websocket-ticket") {
				writeJSON(w, map[string]string{"ticket": "fixture-ticket"})
				return
			}
			writeJSON(w, map[string]any{"authenticated": true, "remoteAddress": r.RemoteAddr})
		case p == "/api/test/site/index.html":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Security-Policy", "sandbox allow-scripts")
			_, _ = io.WriteString(w, `<link rel="stylesheet" href="style.css"><script src="app.js"></script><img src="img/logo.png">`)
		case strings.HasSuffix(p, "style.css"):
			w.Header().Set("Content-Type", "text/css")
			_, _ = io.WriteString(w, "body{width:123px}")
		case strings.HasSuffix(p, "app.js"):
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = io.WriteString(w, `console.log("script ran")`)
		case strings.HasSuffix(p, ".png"):
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(PNG)
		case strings.HasSuffix(p, "stream.mjpeg"):
			w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary=frame")
			flusher, _ := w.(http.Flusher)
			for range MJPEGFrames {
				_, _ = io.WriteString(w, "--frame\r\nContent-Type: image/jpeg\r\n\r\n\xff\xd8\xff\xd9\r\n")
				if flusher != nil {
					flusher.Flush()
				}
				time.Sleep(time.Millisecond)
			}
		case p == "/api/test/upload":
			n, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, strconv.FormatInt(n, 10))
		case p == "/api/test/echo":
			_ = http.NewResponseController(w).EnableFullDuplex()
			w.WriteHeader(http.StatusOK)
			_, _ = io.Copy(w, r.Body)
		case p == "/api/test/video" || p == "/api/test/blob":
			serveBytes(w, r, VideoBytes, func(_, n int) []byte { return bytes.Repeat([]byte{7}, n) })
		case strings.HasPrefix(p, "/api/test/bytes/"):
			size, err := strconv.Atoi(strings.TrimPrefix(p, "/api/test/bytes/"))
			if err != nil || size < 0 {
				http.NotFound(w, r)
				return
			}
			serveBytes(w, r, size, Pattern)
		default:
			http.NotFound(w, r)
		}
	})
}

func serveBytes(w http.ResponseWriter, r *http.Request, total int, content func(offset, n int) []byte) {
	start, size := 0, total
	if m := ranges.FindStringSubmatch(r.Header.Get("Range")); m != nil {
		first, _ := strconv.Atoi(m[1])
		last, _ := strconv.Atoi(m[2])
		start, size = first, last-first+1
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, last, total))
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Content-Length", strconv.Itoa(size))
	}
	for offset := 0; offset < size; offset += 64 << 10 {
		if _, err := w.Write(content(start+offset, min(size-offset, 64<<10))); err != nil {
			return
		}
	}
}
