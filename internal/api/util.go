package api

import (
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/raidiam/mock-tpp/internal/tpp"
)

func writeJSON(w http.ResponseWriter, data any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func writeError(w http.ResponseWriter, err error, status int) {
	writeJSON(w, map[string]string{"error": err.Error()}, status)
}

func renderError(w http.ResponseWriter, r *http.Request, tmpl *template.Template, err error) {
	page := errorPage{
		Error: err.Error(),
	}
	if interactionID := r.Context().Value(InteractionIDKey); interactionID != nil {
		page.InteractionID = interactionID.(string)
	}
	if err := tmpl.ExecuteTemplate(w, "error.html", page); err != nil {
		slog.ErrorContext(r.Context(), "error executing error template", "error", err)
		writeError(w, err, http.StatusInternalServerError)
		return
	}
}

func renderFlowError(w http.ResponseWriter, r *http.Request, tmpl *template.Template, flow *tpp.Flow, err error) {
	page := errorPage{
		Error:  err.Error(),
		FlowID: flow.ID,
	}
	if interactionID := r.Context().Value(InteractionIDKey); interactionID != nil {
		page.InteractionID = interactionID.(string)
	}
	if err := tmpl.ExecuteTemplate(w, "error.html", page); err != nil {
		slog.ErrorContext(r.Context(), "error executing flow error template", "error", err)
		writeError(w, err, http.StatusInternalServerError)
		return
	}
}

func redirect(w http.ResponseWriter, url string) {
	w.Header().Set("Location", url)
	w.WriteHeader(http.StatusFound)
}
