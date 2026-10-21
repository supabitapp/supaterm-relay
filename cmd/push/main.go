package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
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
	store, err := push.OpenStore(cfg.Database)
	if err != nil {
		fmt.Fprintln(os.Stderr, "push: open database:", err)
		os.Exit(1)
	}
	defer store.Close()
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "push: listen:", err)
		os.Exit(1)
	}
	s := push.New(cfg, store, push.NewAPNsHTTPClient(), log)
	envs := make([]string, 0, len(cfg.Credentials))
	for env := range cfg.Credentials {
		envs = append(envs, env)
	}
	log.Info("listening", "address", ln.Addr().String(), "topics", cfg.Topics, "environments", envs)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- s.Serve(ln) }()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "error", err)
			store.Close()
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
