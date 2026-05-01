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

// InactivityCheckArgs are the arguments for the inactivity check job.
type InactivityCheckArgs struct{}

func (InactivityCheckArgs) Kind() string { return "inactivity_check" }

// InactivityCheckWorker disables users who have been inactive beyond the configured threshold.
type InactivityCheckWorker struct {
	river.WorkerDefaults[InactivityCheckArgs]
	AuthService *auth.Service
	Config      config.Config
	Queries     *sqlc.Queries
	Logger      *slog.Logger
}

func (w *InactivityCheckWorker) Work(ctx context.Context, job *river.Job[InactivityCheckArgs]) error {
	deadline := sql.NullTime{Time: time.Now().UTC().Add(-w.Config.Security.InactivityDisableAfter), Valid: true}
	users, err := w.Queries.DisableInactiveUsers(ctx, deadline)
	if err != nil {
		w.Logger.Error("disable inactive users", slog.Any("err", err))
		return err
	}
	if len(users) > 0 {
		w.Logger.Info("disabled inactive users", slog.Int("count", len(users)))
	}
	return nil
}
