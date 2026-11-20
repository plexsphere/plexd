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
	apiTLSAddr := flag.String("api-tls-addr", "", "TLS listen address for the control plane API (host:port); empty runs no such listener")
	check := flag.String("check", "", "healthcheck URL (GET and exit 0/1)")
	dnsAddr := flag.String("dns-addr", "", "DNS stub listen address for UDP and TCP (host:port); empty runs no stub")
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
	tlsCfg, caPEM := mockapi.GenerateCATLSConfig()
	srv.SetTLSCA(caPEM)
	tlsSrv := &http.Server{
		Handler:   srv.TLSHandler(),
		TLSConfig: tlsCfg,
	}
	tlsLnTLS := tls.NewListener(tlsLn, tlsCfg)
	logger.Info("TLS server started", "addr", tlsLn.Addr().String())

	// The control plane API over TLS, for a suite that proves a client trusts
	// the mock's CA from a file. It serves the same handler, bearer gate
	// included, as the plain listener, and presents the same leaf as the
	// local endpoint listener, so only the transport differs.
	var apiTLSSrv *http.Server
	var apiTLSLnTLS net.Listener
	if *apiTLSAddr != "" {
		apiTLSLn, err := net.Listen("tcp", *apiTLSAddr)
		if err != nil {
			logger.Error("API TLS listen failed", "addr", *apiTLSAddr, "error", err)
			os.Exit(1)
		}
		apiTLSSrv = &http.Server{
			Handler:   srv.Handler(),
			TLSConfig: tlsCfg,
		}
		apiTLSLnTLS = tls.NewListener(apiTLSLn, tlsCfg)
		logger.Info("API TLS server started", "addr", apiTLSLn.Addr().String())
	}

	dnsStub, err := startDNSStub(*dnsAddr, logger)
	if err != nil {
		logger.Error("DNS stub listen failed", "addr", *dnsAddr, "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		httpSrv.Close()
		tlsSrv.Close()
		if apiTLSSrv != nil {
			apiTLSSrv.Close()
		}
	}()

	if dnsStub != nil {
		go func() {
			if err := dnsStub.Serve(ctx); err != nil {
				logger.Error("DNS stub serve failed", "error", err)
			}
		}()
	}

	go func() {
		if err := tlsSrv.Serve(tlsLnTLS); err != nil && err != http.ErrServerClosed {
			logger.Error("TLS serve failed", "error", err)
		}
	}()

	if apiTLSSrv != nil {
		go func() {
			if err := apiTLSSrv.Serve(apiTLSLnTLS); err != nil && err != http.ErrServerClosed {
				logger.Error("API TLS serve failed", "error", err)
			}
		}()
	}

	if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		logger.Error("serve failed", "error", err)
		os.Exit(1)
	}
}

// startDNSStub binds the DNS stub on addr, UDP and TCP, and logs the address
// it got, so a suite that passes port 0 learns the port. An empty addr runs
// no stub: it binds nothing and returns nil and no error. A failed bind
// returns the error and logs nothing.
func startDNSStub(addr string, logger *slog.Logger) (*mockapi.DNSStub, error) {
	if addr == "" {
		return nil, nil
	}
	stub, err := mockapi.ListenDNS(addr)
	if err != nil {
		return nil, err
	}
	logger.Info("DNS stub started", "addr", stub.Addr().String())
	return stub, nil
}
