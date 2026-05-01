package river

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"base/internal/auth"
	"base/internal/config"
	"base/internal/mailer"
	riverjobs "base/internal/river/jobs"
	"base/internal/store/sqlc"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/riverqueue/river/rivertype"
)

// sweeperRegistry holds cache sweeper functions that run during cleanup.
type sweeperRegistry struct {
	mu  sync.Mutex
	fns []func(time.Time)
}

func (r *sweeperRegistry) Add(fn func(time.Time)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fns = append(r.fns, fn)
}

func (r *sweeperRegistry) RunAll(now time.Time) {
	r.mu.Lock()
	fns := make([]func(time.Time), len(r.fns))
	copy(fns, r.fns)
	r.mu.Unlock()
	for _, fn := range fns {
		fn(now)
	}
}

// Client wraps a River client with periodic jobs and sweepers.
type Client struct {
	logger   *slog.Logger
	river    *river.Client[pgx.Tx]
	sweepers *sweeperRegistry

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a River client with registered workers and periodic jobs.
func New(ctx context.Context, logger *slog.Logger, db *sql.DB, pool *pgxpool.Pool, mail *mailer.Mailer, authService *auth.Service, cfg config.Config) (*Client, error) {
	if !cfg.River.Enabled {
		return nil, nil
	}

	// Run River migrations.
	migrator, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return nil, fmt.Errorf("create river migrator: %w", err)
	}
	if _, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, &rivermigrate.MigrateOpts{}); err != nil {
		return nil, fmt.Errorf("river migrate up: %w", err)
	}

	q := sqlc.New(db)

	sweepers := &sweeperRegistry{}

	workers := river.NewWorkers()
	river.AddWorker(workers, &riverjobs.EmailOutboxWorker{
		Mailer:  mail,
		Queries: q,
		Logger:  logger,
	})
	river.AddWorker(workers, &riverjobs.CleanupWorker{
		AuthService: authService,
		Config:      cfg,
		Queries:     q,
		Logger:      logger,
		Sweepers:    sweepers,
	})
	river.AddWorker(workers, &riverjobs.InactivityCheckWorker{
		AuthService: authService,
		Config:      cfg,
		Queries:     q,
		Logger:      logger,
	})

	periodicJobs := []*river.PeriodicJob{
		river.NewPeriodicJob(
			river.PeriodicInterval(cfg.River.EmailOutboxEvery),
			func() (river.JobArgs, *river.InsertOpts) {
				return &riverjobs.EmailOutboxArgs{}, nil
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		),
		river.NewPeriodicJob(
			river.PeriodicInterval(cfg.River.CleanupEvery),
			func() (river.JobArgs, *river.InsertOpts) {
				return &riverjobs.CleanupArgs{}, nil
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		),
		river.NewPeriodicJob(
			river.PeriodicInterval(cfg.River.InactivityCheckEvery),
			func() (river.JobArgs, *river.InsertOpts) {
				return &riverjobs.InactivityCheckArgs{}, nil
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		),
	}

	riverClient, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues: map[string]river.QueueConfig{
			river.QueueDefault: {MaxWorkers: cfg.River.MaxWorkers},
		},
		Workers:      workers,
		PeriodicJobs: periodicJobs,
		Logger:       logger,
	})
	if err != nil {
		return nil, fmt.Errorf("create river client: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)

	c := &Client{
		logger:   logger,
		river:    riverClient,
		sweepers: sweepers,
		cancel:   cancel,
	}

	// Run the client in a goroutine.
	c.wg.Go(func() {
		logger.Info("river client starting")
		if err := riverClient.Start(ctx); err != nil {
			logger.Error("river client stopped with error", slog.Any("err", err))
		}
	})

	return c, nil
}

// Stop gracefully shuts down the River client.
func (c *Client) Stop(ctx context.Context) {
	if c == nil {
		return
	}
	c.cancel()
	if err := c.river.Stop(ctx); err != nil {
		c.logger.Error("river client stop error", slog.Any("err", err))
	}
	c.wg.Wait()
}

// Insert inserts a job outside of a transaction.
func (c *Client) Insert(ctx context.Context, args river.JobArgs, opts *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	if c == nil {
		return nil, nil
	}
	return c.river.Insert(ctx, args, opts)
}

// InsertTx inserts a job within a transaction.
func (c *Client) InsertTx(ctx context.Context, tx pgx.Tx, args river.JobArgs, opts *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	if c == nil {
		return nil, nil
	}
	return c.river.InsertTx(ctx, tx, args, opts)
}

// RegisterSweeper registers a function that is called during each cleanup run.
func (c *Client) RegisterSweeper(fn func(time.Time)) {
	if c == nil {
		return
	}
	c.sweepers.Add(fn)
}
