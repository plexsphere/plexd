// Command mockapi runs a mock Central API server for end-to-end testing.
package main

import (
	"context"
	"crypto/tls"
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
	tlsAddr := flag.String("tls-addr", ":8443", "TLS listen address for local endpoints (host:port)")
	check := flag.String("check", "", "healthcheck URL (GET and exit 0/1)")
	flag.Parse()

	// Healthcheck mode: GET the URL and exit with 0 (ok) or 1 (fail).
	if *check != "" {
		resp, err := http.Get(*check)
		if err != nil || resp.StatusCode >= 400 {
			os.Exit(1)
		}
		return
	}

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

	// Start TLS listener for local endpoints.
	tlsLn, err := net.Listen("tcp", *tlsAddr)
	if err != nil {
		logger.Error("TLS listen failed", "addr", *tlsAddr, "error", err)
		os.Exit(1)
	}
	tlsCfg := mockapi.GenerateSelfSignedTLSConfig()
	tlsSrv := &http.Server{
		Handler:   srv.TLSHandler(),
		TLSConfig: tlsCfg,
	}
	tlsLnTLS := tls.NewListener(tlsLn, tlsCfg)
	logger.Info("TLS server started", "addr", tlsLn.Addr().String())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		httpSrv.Close()
		tlsSrv.Close()
	}()

	go func() {
		if err := tlsSrv.Serve(tlsLnTLS); err != nil && err != http.ErrServerClosed {
			logger.Error("TLS serve failed", "error", err)
		}
	}()

	if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		logger.Error("serve failed", "error", err)
		os.Exit(1)
	}
}
