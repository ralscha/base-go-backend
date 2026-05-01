package jobs

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"base/internal/auth"
	"base/internal/config"
	"base/internal/store/sqlc"

	"github.com/riverqueue/river"
)

// CleanupArgs are the arguments for the cleanup job.
type CleanupArgs struct{}

func (CleanupArgs) Kind() string { return "cleanup" }

// SweeperRegistry is the interface for running cache sweepers.
type SweeperRegistry interface {
	RunAll(now time.Time)
}

// CleanupWorker performs periodic cleanup of expired tokens, old emails, and stale rate limit buckets.
type CleanupWorker struct {
	river.WorkerDefaults[CleanupArgs]
	AuthService *auth.Service
	Config      config.Config
	Queries     *sqlc.Queries
	Logger      *slog.Logger
	Sweepers    SweeperRegistry
}

func (w *CleanupWorker) Work(ctx context.Context, job *river.Job[CleanupArgs]) error {
	deletedExpiredTokens, err := w.Queries.DeleteExpiredUserTokens(ctx)
	if err != nil {
		w.Logger.Error("delete expired user tokens", slog.Any("err", err))
	} else if deletedExpiredTokens > 0 {
		w.Logger.Info("deleted expired user tokens", slog.Int64("count", deletedExpiredTokens))
	}

	emailOutboxCutoff := time.Now().UTC().Add(-w.Config.River.EmailOutboxRetention)
	deletedSentEmails, err := w.Queries.DeleteSentEmailsBefore(ctx, sql.NullTime{Time: emailOutboxCutoff, Valid: true})
	if err != nil {
		w.Logger.Error("delete sent emails from outbox", slog.Any("err", err))
	} else if deletedSentEmails > 0 {
		w.Logger.Info("deleted sent emails from outbox", slog.Int64("count", deletedSentEmails))
	}

	deletedFailedEmails, err := w.Queries.DeleteFailedEmailsBefore(ctx, emailOutboxCutoff)
	if err != nil {
		w.Logger.Error("delete failed emails from outbox", slog.Any("err", err))
	} else if deletedFailedEmails > 0 {
		w.Logger.Info("deleted failed emails from outbox", slog.Int64("count", deletedFailedEmails))
	}

	deletedUsedTokens, err := w.Queries.DeleteUsedUserTokens(ctx)
	if err != nil {
		w.Logger.Error("delete used user tokens", slog.Any("err", err))
	} else if deletedUsedTokens > 0 {
		w.Logger.Info("deleted used user tokens", slog.Int64("count", deletedUsedTokens))
	}

	if w.AuthService != nil && w.AuthService.RateLimiter() != nil {
		removed, err := w.AuthService.RateLimiter().DeleteStaleBuckets(ctx, 24*time.Hour)
		if err != nil {
			w.Logger.Error("delete stale rate limit buckets", slog.Any("err", err))
		} else if removed > 0 {
			w.Logger.Info("deleted stale rate limit buckets", slog.Int64("count", removed))
		}
	}

	if w.Sweepers != nil {
		w.Sweepers.RunAll(time.Now().UTC())
	}

	return nil
}
