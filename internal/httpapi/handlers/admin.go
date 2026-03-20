package handlers

import (
	"net/http"

	"base/internal/auth"
	"base/internal/httpapi/jsonio"

	"github.com/alexedwards/scs/v2"
)

type AdminHandler struct {
	Service  *auth.Service
	Sessions *scs.SessionManager
}

func (h AdminHandler) Access(w http.ResponseWriter, r *http.Request) {
	principal, err := h.Service.CurrentUser(r.Context(), h.Sessions.GetInt64(r.Context(), "user_id"))
	if err != nil {
		handleAuthError(w, err)
		return
	}

	jsonio.WriteJSON(w, http.StatusOK, map[string]any{
		"user":  principal,
		"roles": principal.Roles,
	})
}
