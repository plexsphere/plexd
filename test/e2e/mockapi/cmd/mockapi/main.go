// Command mockapi runs a mock Central API server for end-to-end testing.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/plexsphere/plexd/test/e2e/mockapi"
)

func main() {
	addr := flag.String("addr", ":0", "listen address (host:port)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	srv := mockapi.New()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Error("listen failed", "addr", *addr, "error", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "MOCKAPI_ADDR=%s\n", ln.Addr().String())
	logger.Info("mock API server started", "addr", ln.Addr().String())

	httpSrv := &http.Server{Handler: srv.Handler()}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		httpSrv.Close()
	}()

	if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		logger.Error("serve failed", "error", err)
		os.Exit(1)
	}
}
