package app

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"base/internal/auth"
	"base/internal/config"
	"base/internal/database"
	"base/internal/httpapi"
	"base/internal/mailer"
	"base/internal/scheduler"

	"github.com/alexedwards/scs/pgxstore"
	"github.com/alexedwards/scs/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	ratelimit "github.com/ralscha/ratelimiter-pg"
)

type App struct {
	logger    *slog.Logger
	config    config.Config
	db        *sql.DB
	pgxPool   *pgxpool.Pool
	server    *http.Server
	scheduler *scheduler.Scheduler
	sessions  *scs.SessionManager
	sessionDB *pgxstore.PostgresStore
}

func New(ctx context.Context, cfg config.Config) (*App, error) {
	logger := newLogger(cfg.App.LogLevel)
	db, err := database.Open(ctx, cfg.Database)
	if err != nil {
		return nil, err
	}

	pgxPool, err := pgxpool.New(ctx, cfg.Database.URL)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open pgx pool: %w", err)
	}

	if err := database.RunMigrations(ctx, db); err != nil {
		pgxPool.Close()
		_ = db.Close()
		return nil, err
	}

	sessions, sessionDB := newSessionManager(pgxPool, cfg)

	authService, err := auth.NewService(ctx, db, pgxPool, cfg)
	if err != nil {
		pgxPool.Close()
		_ = db.Close()
		return nil, err
	}

	mailService := mailer.New(logger, cfg.Mailer)
	jobScheduler := scheduler.Start(ctx, logger, db, mailService, authService, cfg)

	loginLimiter := ratelimit.New(pgxPool, "public", ratelimit.BucketConfig{
		Capacity:        10,
		RefillPerSecond: 1.0 / 30.0, // 2 tokens/min → 120 attempts/hr sustained
		CostPerRequest:  1,
		DenyRetryFloor:  10 * time.Second,
	})
	if err := loginLimiter.Init(ctx); err != nil {
		pgxPool.Close()
		_ = db.Close()
		return nil, fmt.Errorf("init login rate limiter: %w", err)
	}

	handler := httpapi.NewRouter(db, sessions, authService, loginLimiter, cfg)
	server := &http.Server{
		Addr:              cfg.HTTP.Address,
		Handler:           handler,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}

	return &App{
		logger:    logger,
		config:    cfg,
		db:        db,
		pgxPool:   pgxPool,
		server:    server,
		scheduler: jobScheduler,
		sessions:  sessions,
		sessionDB: sessionDB,
	}, nil
}

func (a *App) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		a.logger.Info("http server listening", slog.String("address", a.server.Addr))
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), a.config.HTTP.ShutdownTimeout)
		defer cancel()
		if err := a.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown server: %w", err)
		}
		a.scheduler.Stop()
		if a.sessionDB != nil {
			a.sessionDB.StopCleanup()
		}
		a.pgxPool.Close()
		return a.db.Close()
	case err := <-errCh:
		a.scheduler.Stop()
		if a.sessionDB != nil {
			a.sessionDB.StopCleanup()
		}
		a.pgxPool.Close()
		closeErr := a.db.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
}

func (a *App) Logger() *slog.Logger {
	return a.logger
}

func newLogger(level string) *slog.Logger {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slogLevel})
	return slog.New(handler)
}

func newSessionManager(pool *pgxpool.Pool, cfg config.Config) (*scs.SessionManager, *pgxstore.PostgresStore) {
	manager := scs.New()
	store := pgxstore.New(pool)
	manager.Store = store
	manager.Cookie.Name = cfg.Session.CookieName
	manager.Cookie.HttpOnly = cfg.Session.HTTPOnly
	manager.Cookie.Persist = cfg.Session.Persist
	manager.Cookie.Secure = cfg.Session.Secure
	manager.Lifetime = cfg.Session.Lifetime
	manager.IdleTimeout = cfg.Session.IdleTimeout

	switch strings.ToLower(cfg.Session.SameSite) {
	case "strict":
		manager.Cookie.SameSite = http.SameSiteStrictMode
	case "none":
		manager.Cookie.SameSite = http.SameSiteNoneMode
	default:
		manager.Cookie.SameSite = http.SameSiteLaxMode
	}

	return manager, store
}
