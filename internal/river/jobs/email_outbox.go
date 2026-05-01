package jobs

import (
	"context"
	"database/sql"
	"log/slog"

	"base/internal/mailer"
	"base/internal/store/sqlc"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// EmailOutboxArgs are the arguments for processing the email outbox.
type EmailOutboxArgs struct{}

func (EmailOutboxArgs) Kind() string { return "email_outbox" }

func (EmailOutboxArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByState: []rivertype.JobState{
		rivertype.JobStateAvailable,
		rivertype.JobStatePending,
		rivertype.JobStateRunning,
		rivertype.JobStateRetryable,
		rivertype.JobStateScheduled,
	}}}
}

// EmailOutboxWorker processes pending emails from the outbox.
type EmailOutboxWorker struct {
	river.WorkerDefaults[EmailOutboxArgs]
	Mailer  *mailer.Mailer
	Queries *sqlc.Queries
	Logger  *slog.Logger
}

func (w *EmailOutboxWorker) Work(ctx context.Context, job *river.Job[EmailOutboxArgs]) error {
	if w.Mailer == nil || !w.Mailer.Enabled() {
		return nil
	}

	emails, err := w.Queries.ListPendingEmails(ctx, 25)
	if err != nil {
		w.Logger.Error("list pending emails", slog.Any("err", err))
		return err
	}

	for _, email := range emails {
		if err := w.Mailer.Send(ctx, email); err != nil {
			markErr := w.Queries.MarkEmailFailed(ctx, sqlc.MarkEmailFailedParams{
				ID:                email.ID,
				LastError:         sql.NullString{String: err.Error(), Valid: true},
				RetryDelaySeconds: 300,
			})
			if markErr != nil {
				w.Logger.Error("mark email failed", slog.Any("err", markErr), slog.Int64("email_id", email.ID))
			}
			continue
		}

		if err := w.Queries.MarkEmailSent(ctx, email.ID); err != nil {
			w.Logger.Error("mark email sent", slog.Any("err", err), slog.Int64("email_id", email.ID))
		}
	}

	return nil
}
