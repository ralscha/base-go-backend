package database

import (
	"context"
	"database/sql"
	"net/url"
	"strings"
	"testing"
	"time"

	"base/internal/config"
	"base/internal/testutil"
)

func TestOpenConnectsToPostgresContainer(t *testing.T) {
	ctx := context.Background()
	databaseURL := startTestPostgres(t, ctx)

	db, err := Open(ctx, config.DatabaseConfig{
		URL:             databaseURL,
		MaxOpenConns:    7,
		MaxIdleConns:    3,
		ConnMaxLifetime: 2 * time.Minute,
		ConnMaxIdleTime: time.Minute,
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var got int
	if err := db.QueryRowContext(ctx, `SELECT 1`).Scan(&got); err != nil {
		t.Fatalf("SELECT 1 error = %v", err)
	}
	if got != 1 {
		t.Fatalf("SELECT 1 = %d, want 1", got)
	}

	stats := db.Stats()
	if stats.MaxOpenConnections != 7 {
		t.Fatalf("MaxOpenConnections = %d, want 7", stats.MaxOpenConnections)
	}
}

func TestOpenReturnsPingErrorForUnavailableDatabase(t *testing.T) {
	ctx := context.Background()
	databaseURL := (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("base_user", strings.Repeat("p", 13)),
		Host:     "127.0.0.1:1",
		Path:     "/base",
		RawQuery: "sslmode=disable&connect_timeout=1",
	}).String()

	_, err := Open(ctx, config.DatabaseConfig{
		URL:             databaseURL,
		MaxOpenConns:    1,
		MaxIdleConns:    1,
		ConnMaxLifetime: time.Second,
		ConnMaxIdleTime: time.Second,
	})
	if err == nil {
		t.Fatal("Open() error = nil, want ping failure")
	}
	if !strings.Contains(err.Error(), "ping database") {
		t.Fatalf("Open() error = %v, want ping database error", err)
	}
}

func TestRunMigrationsCreatesSchemaAndCanBeReapplied(t *testing.T) {
	ctx := context.Background()
	databaseURL := startTestPostgres(t, ctx)
	db := openTestDB(t, ctx, databaseURL)

	if err := RunMigrations(ctx, db); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	if err := RunMigrations(ctx, db); err != nil {
		t.Fatalf("RunMigrations() second run error = %v", err)
	}

	assertRelationExists(t, ctx, db, "users")
	assertRelationExists(t, ctx, db, "oauth_accounts")
	assertRelationExists(t, ctx, db, "scheduled_jobs")

	var passwordHashType sql.NullString
	if err := db.QueryRowContext(ctx, `
		SELECT data_type
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND table_name = 'users'
		  AND column_name = 'password_hash'
	`).Scan(&passwordHashType); err != nil {
		t.Fatalf("query users.password_hash column: %v", err)
	}
	if !passwordHashType.Valid || passwordHashType.String != "text" {
		t.Fatalf("users.password_hash data type = %q, want text", passwordHashType.String)
	}

	var roleCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM roles WHERE name IN ('admin', 'user')`).Scan(&roleCount); err != nil {
		t.Fatalf("count seeded roles: %v", err)
	}
	if roleCount != 2 {
		t.Fatalf("seeded role count = %d, want 2", roleCount)
	}

	var triggerCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_trigger WHERE tgname = 'trg_users_updated_at'`).Scan(&triggerCount); err != nil {
		t.Fatalf("count users trigger: %v", err)
	}
	if triggerCount != 1 {
		t.Fatalf("users trigger count = %d, want 1", triggerCount)
	}

	var functionCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_proc WHERE proname = 'set_updated_at'`).Scan(&functionCount); err != nil {
		t.Fatalf("count set_updated_at function: %v", err)
	}
	if functionCount == 0 {
		t.Fatal("expected set_updated_at function to exist after migrations")
	}
}

func startTestPostgres(t *testing.T, ctx context.Context) string {
	t.Helper()

	return testutil.FreshPostgresDatabaseURL(t, ctx)
}

func openTestDB(t *testing.T, ctx context.Context, databaseURL string) *sql.DB {
	t.Helper()

	db, err := Open(ctx, config.DatabaseConfig{
		URL:             databaseURL,
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
		ConnMaxIdleTime: time.Minute,
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func assertRelationExists(t *testing.T, ctx context.Context, db *sql.DB, relation string) {
	t.Helper()

	var found sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.' || $1)`, relation).Scan(&found); err != nil {
		t.Fatalf("to_regclass(%s) error = %v", relation, err)
	}
	if !found.Valid || found.String == "" {
		t.Fatalf("relation %q does not exist", relation)
	}
}
