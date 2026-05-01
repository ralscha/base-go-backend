package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"base/internal/testutil"
)

func TestRunStartsAndStopsApp(t *testing.T) {
	ctx := context.Background()
	databaseURL := testutil.FreshPostgresDatabaseURL(t, ctx)

	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(workingDir, "..", ".."))
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatalf("Chdir(repo root) error = %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(workingDir)
	})

	t.Setenv("BASE_APP_ENV", "test")
	t.Setenv("BASE_DATABASE_URL", databaseURL)
	t.Setenv("BASE_DATABASE_MAX_OPEN_CONNS", "5")
	t.Setenv("BASE_DATABASE_MAX_IDLE_CONNS", "2")
	t.Setenv("BASE_RIVER_ENABLED", "false")
	t.Setenv("BASE_MAILER_ENABLED", "false")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close() error = %v", err)
	}
	t.Setenv("BASE_HTTP_ADDRESS", address)

	runCtx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(runCtx)
	}()

	client := &http.Client{Timeout: time.Second}
	healthURL := fmt.Sprintf("http://%s/health", address)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("timed out waiting for app health endpoint")
		}
		resp, err := client.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("run() returned before health check: %v", err)
			}
			t.Fatal("run() returned before health check without error")
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("run() error = %v", err)
	}
}
