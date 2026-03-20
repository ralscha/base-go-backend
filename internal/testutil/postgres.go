package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

const postgresImage = "postgres:18-alpine"

var (
	sharedPostgresOnce sync.Once
	sharedPostgresURL  string
	sharedPostgresErr  error

	nonDatabaseNameChars = regexp.MustCompile(`[^a-z0-9_]+`)
)

func FreshPostgresDatabaseURL(t *testing.T, ctx context.Context) string {
	t.Helper()

	adminURL, err := sharedPostgresConnectionString(ctx)
	if err != nil {
		t.Fatalf("sharedPostgresConnectionString() error = %v", err)
	}

	databaseName := makeDatabaseName(t.Name())
	adminDB, err := sql.Open("postgres", adminURL)
	if err != nil {
		t.Fatalf("sql.Open(admin) error = %v", err)
	}
	defer func() { _ = adminDB.Close() }()

	if _, err := adminDB.ExecContext(ctx, `CREATE DATABASE `+quoteIdentifier(databaseName)); err != nil {
		t.Fatalf("CREATE DATABASE %s error = %v", databaseName, err)
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cleanupDB, err := sql.Open("postgres", adminURL)
		if err != nil {
			t.Fatalf("sql.Open(cleanup admin) error = %v", err)
		}
		defer func() { _ = cleanupDB.Close() }()

		if _, err := cleanupDB.ExecContext(cleanupCtx, `
			SELECT pg_terminate_backend(pid)
			FROM pg_stat_activity
			WHERE datname = $1 AND pid <> pg_backend_pid()
		`, databaseName); err != nil {
			t.Fatalf("terminate connections for %s error = %v", databaseName, err)
		}

		if _, err := cleanupDB.ExecContext(cleanupCtx, `DROP DATABASE IF EXISTS `+quoteIdentifier(databaseName)); err != nil {
			t.Fatalf("DROP DATABASE %s error = %v", databaseName, err)
		}
	})

	databaseURL, err := withDatabaseName(adminURL, databaseName)
	if err != nil {
		t.Fatalf("withDatabaseName(%s) error = %v", databaseName, err)
	}

	return databaseURL
}

func sharedPostgresConnectionString(ctx context.Context) (string, error) {
	sharedPostgresOnce.Do(func() {
		container, err := tcpostgres.Run(
			ctx,
			postgresImage,
			tcpostgres.BasicWaitStrategies(),
			tcpostgres.WithDatabase("base"),
			tcpostgres.WithUsername("base_user"),
			tcpostgres.WithPassword("base_password"),
		)
		if err != nil {
			sharedPostgresErr = fmt.Errorf("postgres.Run(): %w", err)
			return
		}

		sharedPostgresURL, sharedPostgresErr = container.ConnectionString(ctx, "sslmode=disable")
		if sharedPostgresErr != nil {
			sharedPostgresErr = fmt.Errorf("ConnectionString(): %w", sharedPostgresErr)
		}
	})

	return sharedPostgresURL, sharedPostgresErr
}

func makeDatabaseName(testName string) string {
	sanitized := strings.ToLower(testName)
	sanitized = nonDatabaseNameChars.ReplaceAllString(sanitized, "_")
	sanitized = strings.Trim(sanitized, "_")
	if sanitized == "" {
		sanitized = "test"
	}

	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	prefix := "test_"
	maxBaseLen := 63 - len(prefix) - 1 - len(suffix)
	if len(sanitized) > maxBaseLen {
		sanitized = sanitized[:maxBaseLen]
	}

	return prefix + sanitized + "_" + suffix
}

func withDatabaseName(rawURL string, databaseName string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	parsed.Path = "/" + databaseName
	return parsed.String(), nil
}

func quoteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}
