package scheduler

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"base/internal/config"
	"base/internal/database"
	"base/internal/store/sqlc"

	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestStartReturnsNilWhenDisabled(t *testing.T) {
	scheduler := Start(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil, nil, config.Config{
		Scheduler: config.SchedulerConfig{Enabled: false},
	})
	if scheduler != nil {
		t.Fatalf("Start() = %v, want nil when scheduler disabled", scheduler)
	}
}

func TestStopHandlesNilReceiver(t *testing.T) {
	var scheduler *Scheduler
	scheduler.Stop()
}

func TestLoopSkipsNonPositiveIntervals(t *testing.T) {
	scheduler := &Scheduler{}
	ctx := t.Context()

	var calls atomic.Int32
	scheduler.loop(ctx, 0, func(context.Context) {
		calls.Add(1)
	})

	if got := calls.Load(); got != 0 {
		t.Fatalf("job calls = %d, want 0", got)
	}
}

func TestLoopRunsJobAndStopsOnCancel(t *testing.T) {
	scheduler := &Scheduler{}
	ctx, cancel := context.WithCancel(context.Background())

	var calls atomic.Int32
	scheduler.loop(ctx, 5*time.Millisecond, func(context.Context) {
		calls.Add(1)
	})

	time.Sleep(20 * time.Millisecond)
	cancel()
	scheduler.wg.Wait()

	if got := calls.Load(); got == 0 {
		t.Fatal("job calls = 0, want at least one execution")
	}
}

func TestCleanupRemovesExpiredAndRevokedRecords(t *testing.T) {
	ctx := context.Background()
	db, queries := newSchedulerTestDB(t, ctx)

	user, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "cleanup-user", Email: "cleanup@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	if err := queries.CreateUserSessionRecord(ctx, sqlc.CreateUserSessionRecordParams{
		Token:    "expired-session",
		UserID:   user.ID,
		DeviceID: "device-1",
		Expiry:   time.Now().UTC().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("CreateUserSessionRecord(expired) error = %v", err)
	}
	if err := queries.CreateUserSessionRecord(ctx, sqlc.CreateUserSessionRecordParams{
		Token:    "revoked-session",
		UserID:   user.ID,
		DeviceID: "device-2",
		Expiry:   time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateUserSessionRecord(revoked) error = %v", err)
	}
	if err := queries.CreateUserSessionRecord(ctx, sqlc.CreateUserSessionRecordParams{
		Token:    "active-session",
		UserID:   user.ID,
		DeviceID: "device-3",
		Expiry:   time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateUserSessionRecord(active) error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE user_sessions SET revoked_at = NOW() WHERE token = 'revoked-session'`); err != nil {
		t.Fatalf("mark revoked session: %v", err)
	}

	if _, err := queries.CreateUserToken(ctx, sqlc.CreateUserTokenParams{
		UserID:    user.ID,
		Kind:      sqlc.TokenKindPasswordReset,
		TokenHash: "expired-token",
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("CreateUserToken(expired) error = %v", err)
	}
	usedToken, err := queries.CreateUserToken(ctx, sqlc.CreateUserTokenParams{
		UserID:    user.ID,
		Kind:      sqlc.TokenKindEmailVerification,
		TokenHash: "used-token",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateUserToken(used) error = %v", err)
	}
	if err := queries.UseUserToken(ctx, usedToken.ID); err != nil {
		t.Fatalf("UseUserToken() error = %v", err)
	}
	if _, err := queries.CreateUserToken(ctx, sqlc.CreateUserTokenParams{
		UserID:    user.ID,
		Kind:      sqlc.TokenKindAccountRecovery,
		TokenHash: "active-token",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("CreateUserToken(active) error = %v", err)
	}

	scheduler := &Scheduler{logger: discardLogger(), q: queries}
	scheduler.cleanup(ctx)

	assertCount(t, ctx, db, `SELECT COUNT(*) FROM user_sessions`, 1)
	assertCount(t, ctx, db, `SELECT COUNT(*) FROM user_sessions WHERE token = 'active-session'`, 1)
	assertCount(t, ctx, db, `SELECT COUNT(*) FROM user_tokens`, 1)
	assertCount(t, ctx, db, `SELECT COUNT(*) FROM user_tokens WHERE token_hash = 'active-token'`, 1)
}

func TestDisableInactiveUsersDisablesOnlyStaleAccounts(t *testing.T) {
	ctx := context.Background()
	db, queries := newSchedulerTestDB(t, ctx)

	staleUser, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "stale-user", Email: "stale@example.com"})
	if err != nil {
		t.Fatalf("CreateUser(stale) error = %v", err)
	}
	recentUser, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "recent-user", Email: "recent@example.com"})
	if err != nil {
		t.Fatalf("CreateUser(recent) error = %v", err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE users SET created_at = NOW() - INTERVAL '48 hours' WHERE id = $1`, staleUser.ID); err != nil {
		t.Fatalf("age stale user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE users SET last_login_at = NOW() - INTERVAL '72 hours' WHERE id = $1`, staleUser.ID); err != nil {
		t.Fatalf("set stale last_login_at: %v", err)
	}

	scheduler := &Scheduler{
		logger: discardLogger(),
		q:      queries,
		cfg: config.Config{
			Security: config.SecurityConfig{InactivityDisableAfter: 24 * time.Hour},
		},
	}
	scheduler.disableInactiveUsers(ctx)

	staleUserAfter, err := queries.GetUserByID(ctx, staleUser.ID)
	if err != nil {
		t.Fatalf("GetUserByID(stale) error = %v", err)
	}
	if staleUserAfter.IsActive {
		t.Fatal("expected stale user to be disabled")
	}
	if !staleUserAfter.DisabledReason.Valid || staleUserAfter.DisabledReason.String != "inactivity" {
		t.Fatalf("DisabledReason = %+v, want inactivity", staleUserAfter.DisabledReason)
	}
	if !staleUserAfter.DisabledAt.Valid {
		t.Fatal("expected stale user DisabledAt to be set")
	}

	recentUserAfter, err := queries.GetUserByID(ctx, recentUser.ID)
	if err != nil {
		t.Fatalf("GetUserByID(recent) error = %v", err)
	}
	if !recentUserAfter.IsActive {
		t.Fatal("expected recent user to remain active")
	}
}

func newSchedulerTestDB(t *testing.T, ctx context.Context) (*sql.DB, *sqlc.Queries) {
	t.Helper()

	container, err := tcpostgres.Run(
		ctx,
		"postgres:18-alpine",
		tcpostgres.BasicWaitStrategies(),
		tcpostgres.WithDatabase("base"),
		tcpostgres.WithUsername("base_user"),
		tcpostgres.WithPassword("base_password"),
	)
	if err != nil {
		t.Fatalf("postgres.Run() error = %v", err)
	}
	t.Cleanup(func() {
		terminateCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = container.Terminate(terminateCtx)
	})

	databaseURL, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("ConnectionString() error = %v", err)
	}

	db, err := database.Open(ctx, config.DatabaseConfig{
		URL:             databaseURL,
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
		ConnMaxIdleTime: time.Minute,
	})
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if err := database.RunMigrations(ctx, db); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}

	return db, sqlc.New(db)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func assertCount(t *testing.T, ctx context.Context, db *sql.DB, query string, want int) {
	t.Helper()

	var got int
	if err := db.QueryRowContext(ctx, query).Scan(&got); err != nil {
		t.Fatalf("count query %q error = %v", query, err)
	}
	if got != want {
		t.Fatalf("count query %q = %d, want %d", query, got, want)
	}
}
