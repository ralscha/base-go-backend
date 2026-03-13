package httpapi

import (
	"database/sql"
	"net/http"

	"base/internal/auth"
	"base/internal/config"
	"base/internal/httpapi/handlers"
	appmw "base/internal/httpapi/middleware"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	ratelimit "github.com/ralscha/ratelimiter-pg"
)

func NewRouter(db *sql.DB, sessions *scs.SessionManager, authService *auth.Service, loginLimiter *ratelimit.RateLimiter, cfg config.Config) http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.RealIP)
	if cfg.App.Env != "production" {
		r.Use(chimw.Logger)
	}
	r.Use(chimw.Recoverer)
	if cfg.HTTP.WriteTimeout > 0 {
		r.Use(chimw.Timeout(cfg.HTTP.WriteTimeout))
	}
	r.Use(chimw.NoCache)

	health := handlers.HealthHandler{DB: db}
	authHandler := handlers.AuthHandler{Service: authService, Sessions: sessions, Secure: cfg.Session.Secure, LoginRateLimiter: loginLimiter}
	adminHandler := handlers.AdminHandler{Service: authService, Sessions: sessions}

	r.Get("/health", health.Live)
	r.Get("/readiness", health.Ready)

	r.Route("/api/v1", func(api chi.Router) {
		api.Route("/auth", func(public chi.Router) {
			public.Post("/register", authHandler.Register)
			public.Get("/verify-email", authHandler.VerifyEmail)
			public.Post("/account-recovery/request", authHandler.RequestAccountRecovery)
			public.Post("/account-recovery/confirm", authHandler.RecoverAccount)
			public.Post("/password-reset/request", authHandler.RequestPasswordReset)
			public.Post("/password-reset/confirm", authHandler.ResetPassword)

			public.Group(func(sessioned chi.Router) {
				sessioned.Use(sessions.LoadAndSave)
				sessioned.Post("/login", authHandler.Login)
				sessioned.Get("/oauth/{provider}/start", authHandler.StartOAuth)
				sessioned.Get("/oauth/{provider}/callback", authHandler.CompleteOAuth)
				sessioned.Post("/passkeys/login/start", authHandler.BeginPasskeyLogin)
				sessioned.Post("/passkeys/login/finish", authHandler.FinishPasskeyLogin)
			})

			public.Group(func(protected chi.Router) {
				protected.Use(sessions.LoadAndSave)
				protected.Use(appmw.RequireAuthenticated(sessions))
				protected.Post("/logout", authHandler.Logout)
				protected.Get("/me", authHandler.Me)
				protected.Post("/passkeys/register/start", authHandler.BeginPasskeyRegistration)
				protected.Post("/passkeys/register/finish", authHandler.FinishPasskeyRegistration)
				protected.Post("/totp/setup", authHandler.SetupTOTP)
				protected.Post("/totp/enable", authHandler.EnableTOTP)
				protected.Post("/totp/disable", authHandler.DisableTOTP)
			})
		})

		api.Route("/admin", func(admin chi.Router) {
			admin.Use(sessions.LoadAndSave)
			admin.Use(appmw.RequireAuthenticated(sessions))
			admin.Use(appmw.RequireRoles(sessions, "admin"))
			admin.Get("/access", adminHandler.Access)
		})
	})

	return r
}
