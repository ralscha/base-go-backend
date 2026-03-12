package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"base/internal/app"
	"base/internal/config"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if err := run(ctx); err != nil {
		stop()
		os.Exit(1)
	}
	stop()
}

func run(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config", slog.Any("err", err))
		return err
	}

	application, err := app.New(ctx, cfg)
	if err != nil {
		slog.Error("create app", slog.Any("err", err))
		return err
	}

	if err := application.Run(ctx); err != nil {
		application.Logger().Error("run app", slog.Any("err", err))
		return err
	}

	return nil
}
