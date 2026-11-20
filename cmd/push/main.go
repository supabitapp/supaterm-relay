package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/supabitapp/supaterm-relay/internal/push"
)

const shutdownTimeout = 15 * time.Second

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := push.LoadConfig(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "push: invalid configuration:", err)
		os.Exit(2)
	}
	s, err := push.New(cfg, log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "push: open revocations:", err)
		os.Exit(1)
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "push: listen:", err)
		os.Exit(1)
	}
	log.Info("listening",
		"address", ln.Addr().String(),
		"publicURL", cfg.PublicURL,
		"apnsEnvironments", slices.Sorted(maps.Keys(cfg.APNs.Keys)),
		"apnsTopics", cfg.APNs.Topics,
		"fcm", cfg.FCM != nil,
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- s.Serve(ln) }()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := s.Shutdown(shutdown); err != nil {
		log.Warn("shutdown", "error", err)
	}
}
