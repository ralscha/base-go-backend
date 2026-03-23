package scheduler

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"base/internal/config"
	"base/internal/database"
	"base/internal/mailer"
	"base/internal/store/sqlc"
	"base/internal/testutil"
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

func TestCleanupRemovesExpiredAndUsedTokens(t *testing.T) {
	ctx := context.Background()
	db, queries := newSchedulerTestDB(t, ctx)

	user, err := queries.CreateUser(ctx, sqlc.CreateUserParams{Username: "cleanup-user", Email: "cleanup@example.com"})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
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

	oldSentEmail, err := queries.EnqueueEmail(ctx, sqlc.EnqueueEmailParams{
		Template:    "welcome",
		Recipient:   "old-sent@example.com",
		Subject:     "Old Sent",
		Payload:     []byte(`{"name":"old sent"}`),
		AvailableAt: time.Now().UTC().Add(-48 * time.Hour),
	})
	if err != nil {
		t.Fatalf("EnqueueEmail(old sent) error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE email_outbox SET sent_at = $2, updated_at = $2 WHERE id = $1`, oldSentEmail.ID, time.Now().UTC().Add(-48*time.Hour)); err != nil {
		t.Fatalf("age old sent email: %v", err)
	}

	oldFailedEmail, err := queries.EnqueueEmail(ctx, sqlc.EnqueueEmailParams{
		Template:    "welcome",
		Recipient:   "old-failed@example.com",
		Subject:     "Old Failed",
		Payload:     []byte(`{"name":"old failed"}`),
		AvailableAt: time.Now().UTC().Add(-48 * time.Hour),
	})
	if err != nil {
		t.Fatalf("EnqueueEmail(old failed) error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE email_outbox SET attempts = 2, last_error = 'smtp timeout', available_at = $2 WHERE id = $1`, oldFailedEmail.ID, time.Now().UTC().Add(-48*time.Hour)); err != nil {
		t.Fatalf("age old failed email: %v", err)
	}

	recentSentEmail, err := queries.EnqueueEmail(ctx, sqlc.EnqueueEmailParams{
		Template:    "welcome",
		Recipient:   "recent-sent@example.com",
		Subject:     "Recent Sent",
		Payload:     []byte(`{"name":"recent sent"}`),
		AvailableAt: time.Now().UTC().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("EnqueueEmail(recent sent) error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE email_outbox SET sent_at = $2, updated_at = $2 WHERE id = $1`, recentSentEmail.ID, time.Now().UTC().Add(-6*time.Hour)); err != nil {
		t.Fatalf("set recent sent email: %v", err)
	}

	recentFailedEmail, err := queries.EnqueueEmail(ctx, sqlc.EnqueueEmailParams{
		Template:    "welcome",
		Recipient:   "recent-failed@example.com",
		Subject:     "Recent Failed",
		Payload:     []byte(`{"name":"recent failed"}`),
		AvailableAt: time.Now().UTC().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("EnqueueEmail(recent failed) error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE email_outbox SET attempts = 1, last_error = 'smtp timeout', available_at = $2 WHERE id = $1`, recentFailedEmail.ID, time.Now().UTC().Add(-6*time.Hour)); err != nil {
		t.Fatalf("set recent failed email: %v", err)
	}

	scheduler := &Scheduler{logger: discardLogger(), q: queries, cfg: config.Config{Scheduler: config.SchedulerConfig{EmailOutboxRetention: 24 * time.Hour}}}
	scheduler.cleanup(ctx)

	assertCount(t, ctx, db, `SELECT COUNT(*) FROM user_tokens`)
	assertCount(t, ctx, db, `SELECT COUNT(*) FROM user_tokens WHERE token_hash = 'active-token'`)
	assertCount(t, ctx, db, `SELECT COUNT(*) FROM email_outbox WHERE id = $1`, recentSentEmail.ID)
	assertCount(t, ctx, db, `SELECT COUNT(*) FROM email_outbox WHERE id = $1`, recentFailedEmail.ID)

	var oldSentCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM email_outbox WHERE id = $1`, oldSentEmail.ID).Scan(&oldSentCount); err != nil {
		t.Fatalf("count old sent email error = %v", err)
	}
	if oldSentCount != 0 {
		t.Fatalf("old sent email count = %d, want 0", oldSentCount)
	}

	var oldFailedCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM email_outbox WHERE id = $1`, oldFailedEmail.ID).Scan(&oldFailedCount); err != nil {
		t.Fatalf("count old failed email error = %v", err)
	}
	if oldFailedCount != 0 {
		t.Fatalf("old failed email count = %d, want 0", oldFailedCount)
	}
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

func TestProcessOutboxLeavesEmailPendingWhenMailerDisabled(t *testing.T) {
	ctx := context.Background()
	db, queries := newSchedulerTestDB(t, ctx)

	queuedEmail, err := queries.EnqueueEmail(ctx, sqlc.EnqueueEmailParams{
		Template:    "welcome",
		Recipient:   "disabled@example.com",
		Subject:     "Hello",
		Payload:     []byte(`{"name":"alice"}`),
		AvailableAt: time.Now().UTC().Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("EnqueueEmail() error = %v", err)
	}

	scheduler := &Scheduler{
		logger: discardLogger(),
		mail:   nil,
		q:      queries,
	}
	scheduler.processOutbox(ctx)

	assertCount(t, ctx, db, `SELECT COUNT(*) FROM email_outbox WHERE id = $1 AND sent_at IS NULL AND last_error IS NULL`, queuedEmail.ID)
	assertCount(t, ctx, db, `SELECT COUNT(*) FROM email_outbox`)
}

func TestProcessOutboxMarksEmailFailedWhenSendFails(t *testing.T) {
	ctx := context.Background()
	db, queries := newSchedulerTestDB(t, ctx)

	queuedEmail, err := queries.EnqueueEmail(ctx, sqlc.EnqueueEmailParams{
		Template:    "welcome",
		Recipient:   "failure@example.com",
		Subject:     "Hello",
		Payload:     []byte(`{"name":"alice"}`),
		AvailableAt: time.Now().UTC().Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("EnqueueEmail() error = %v", err)
	}

	scheduler := &Scheduler{
		logger: discardLogger(),
		mail: mailer.New(discardLogger(), config.MailerConfig{
			Enabled: true,
			From:    "from@example.com",
			Host:    "127.0.0.1",
			Port:    1,
		}),
		q: queries,
	}
	scheduler.processOutbox(ctx)

	assertCount(t, ctx, db, `SELECT COUNT(*) FROM email_outbox WHERE id = $1 AND sent_at IS NULL AND last_error IS NOT NULL`, queuedEmail.ID)

	var attempts int32
	var lastError sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT attempts, last_error FROM email_outbox WHERE id = $1`, queuedEmail.ID).Scan(&attempts, &lastError); err != nil {
		t.Fatalf("query email_outbox error = %v", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
	if !lastError.Valid || strings.TrimSpace(lastError.String) == "" {
		t.Fatalf("last_error = %+v, want populated failure", lastError)
	}
}

func newSchedulerTestDB(t *testing.T, ctx context.Context) (*sql.DB, *sqlc.Queries) {
	t.Helper()

	databaseURL := testutil.FreshPostgresDatabaseURL(t, ctx)

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

func assertCount(t *testing.T, ctx context.Context, db *sql.DB, query string, args ...any) {
	t.Helper()

	var got int
	if err := db.QueryRowContext(ctx, query, args...).Scan(&got); err != nil {
		t.Fatalf("count query %q error = %v", query, err)
	}
	if got != 1 {
		t.Fatalf("count query %q = %d, want %d", query, got, 1)
	}
}
