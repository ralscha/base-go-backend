package scheduler

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"base/internal/auth"
	"base/internal/config"
	"base/internal/mailer"
	"base/internal/store/sqlc"
)

type Scheduler struct {
	logger *slog.Logger
	mail   *mailer.Mailer
	q      *sqlc.Queries
	auth   *auth.Service
	cfg    config.Config

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func Start(parent context.Context, logger *slog.Logger, db *sql.DB, mail *mailer.Mailer, authService *auth.Service, cfg config.Config) *Scheduler {
	if !cfg.Scheduler.Enabled {
		return nil
	}

	ctx, cancel := context.WithCancel(parent)
	s := &Scheduler{
		logger: logger,
		mail:   mail,
		q:      sqlc.New(db),
		auth:   authService,
		cfg:    cfg,
		cancel: cancel,
	}

	s.loop(ctx, cfg.Scheduler.EmailOutboxEvery, s.processOutbox)
	s.loop(ctx, cfg.Scheduler.CleanupEvery, s.cleanup)
	s.loop(ctx, cfg.Scheduler.InactivityCheckEvery, s.disableInactiveUsers)

	return s
}

func (s *Scheduler) Stop() {
	if s == nil {
		return
	}
	s.cancel()
	s.wg.Wait()
}

func (s *Scheduler) loop(ctx context.Context, interval time.Duration, job func(context.Context)) {
	if interval <= 0 {
		return
	}

	s.wg.Go(func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		job(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				job(ctx)
			}
		}
	})
}

func (s *Scheduler) processOutbox(ctx context.Context) {
	if s.mail == nil || !s.mail.Enabled() {
		return
	}

	emails, err := s.q.ListPendingEmails(ctx, 25)
	if err != nil {
		s.logger.Error("list pending emails", slog.Any("err", err))
		return
	}

	for _, email := range emails {
		if err := s.mail.Send(ctx, email); err != nil {
			markErr := s.q.MarkEmailFailed(ctx, sqlc.MarkEmailFailedParams{
				ID:        email.ID,
				LastError: sql.NullString{String: err.Error(), Valid: true},
				Column3:   300,
			})
			if markErr != nil {
				s.logger.Error("mark email failed", slog.Any("err", markErr), slog.Int64("email_id", email.ID))
			}
			continue
		}

		if err := s.q.MarkEmailSent(ctx, email.ID); err != nil {
			s.logger.Error("mark email sent", slog.Any("err", err), slog.Int64("email_id", email.ID))
		}
	}
}

func (s *Scheduler) cleanup(ctx context.Context) {
	deletedExpiredTokens, err := s.q.DeleteExpiredUserTokens(ctx)
	if err != nil {
		s.logger.Error("delete expired user tokens", slog.Any("err", err))
	} else if deletedExpiredTokens > 0 {
		s.logger.Info("deleted expired user tokens", slog.Int64("count", deletedExpiredTokens))
	}

	deletedUsedTokens, err := s.q.DeleteUsedUserTokens(ctx)
	if err != nil {
		s.logger.Error("delete used user tokens", slog.Any("err", err))
	} else if deletedUsedTokens > 0 {
		s.logger.Info("deleted used user tokens", slog.Int64("count", deletedUsedTokens))
	}

	if s.auth != nil && s.auth.RateLimiter() != nil {
		removed, err := s.auth.RateLimiter().DeleteStaleBuckets(ctx, 24*time.Hour)
		if err != nil {
			s.logger.Error("delete stale rate limit buckets", slog.Any("err", err))
		} else if removed > 0 {
			s.logger.Info("deleted stale rate limit buckets", slog.Int64("count", removed))
		}
	}
}

func (s *Scheduler) disableInactiveUsers(ctx context.Context) {
	deadline := sql.NullTime{Time: time.Now().UTC().Add(-s.cfg.Security.InactivityDisableAfter), Valid: true}
	users, err := s.q.DisableInactiveUsers(ctx, deadline)
	if err != nil {
		s.logger.Error("disable inactive users", slog.Any("err", err))
		return
	}
	if len(users) > 0 {
		s.logger.Info("disabled inactive users", slog.Int("count", len(users)))
	}
}
