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

	"github.com/cloudflare/cfssl/console/auth"
	consoleconfig "github.com/cloudflare/cfssl/console/config"
	"github.com/cloudflare/cfssl/console/httpapi"
	"github.com/cloudflare/cfssl/console/pki"
	"github.com/cloudflare/cfssl/console/security"
	"github.com/cloudflare/cfssl/console/store"
	"github.com/cloudflare/cfssl/console/tsa"
	webassets "github.com/cloudflare/cfssl/web"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	if err := run(logger); err != nil {
		logger.Error("PKI-Console stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	if command != "serve" && command != "worker" && command != "migrate" && command != "healthcheck" && command != "auth-check" {
		return fmt.Errorf("usage: pki-console [serve|worker|migrate|healthcheck|auth-check]")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if command == "auth-check" {
		return runAuthCheck(ctx, os.Args[2:], os.Stdin, os.Stdout)
	}
	cfg, err := consoleconfig.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	if command == "healthcheck" {
		return healthcheck(ctx, cfg)
	}
	if command == "migrate" {
		return store.Migrate(ctx, cfg.DatabaseURL)
	}
	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	data := store.New(pool)
	var authService *auth.Service
	if command == "serve" {
		authService, err = auth.NewService(data, cfg)
		if err != nil {
			return err
		}
		root, err := authService.BootstrapRoot(ctx)
		if err != nil {
			return fmt.Errorf("bootstrap root account: %w", err)
		}
		logger.Info("root account synchronized", "user_id", root.ID, "email", cfg.RootUserEmail)
	}
	pkiService, err := pki.NewService(data, security.Keyring{ActiveID: cfg.MasterKeyActiveID, Keys: cfg.MasterKeys}, cfg.PublicBaseURL.String())
	if err != nil {
		return err
	}
	tsaService, err := tsa.NewService(data, security.Keyring{ActiveID: cfg.MasterKeyActiveID, Keys: cfg.MasterKeys},
		tsa.NewSystemTimeSource(cfg.TSAMaxClockUncertainty, !cfg.DevelopmentInsecure))
	if err != nil {
		return err
	}
	if command == "worker" {
		return runWorker(ctx, pkiService, logger, instanceID())
	}
	api, err := httpapi.New(cfg, data, authService, pkiService, tsaService, logger)
	if err != nil {
		return err
	}
	if err := api.MountFrontend(webassets.Files()); err != nil {
		return err
	}
	httpapi.Version = version
	server := &http.Server{
		Addr: cfg.ListenAddress, Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 32 << 10,
	}
	go func() {
		if err := runWorker(ctx, pkiService, logger, instanceID()); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("issuance worker stopped", "error", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	logger.Info("PKI-Console listening", "address", cfg.ListenAddress,
		"console_host", cfg.ConsoleHostname, "public_host", cfg.PublicHostname)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func healthcheck(ctx context.Context, cfg consoleconfig.Config) error {
	requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	host, port, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil {
		if cfg.ListenAddress == "" || cfg.ListenAddress[0] != ':' {
			return fmt.Errorf("invalid PKI_LISTEN_ADDRESS: %w", err)
		}
		host, port = "", cfg.ListenAddress[1:]
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet,
		"http://"+net.JoinHostPort(host, port)+"/api/v1/health/live", nil)
	if err != nil {
		return err
	}
	req.Host = cfg.ConsoleHostname
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func runWorker(ctx context.Context, service *pki.Service, logger *slog.Logger, workerID string) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		_, err := service.ProcessOne(ctx, workerID)
		if err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, context.Canceled) {
			logger.Error("certificate issuance failed", "worker_id", workerID, "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func instanceID() string {
	host, _ := os.Hostname()
	return fmt.Sprintf("%s-%d", host, os.Getpid())
}
