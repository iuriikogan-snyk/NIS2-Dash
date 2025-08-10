package server

import (
	"log/slog"
	"net/http"

	"github.com/iuriikogan-snyk/NIS2-Dash/backend/internal/config"
)

// NewServer creates and configures an HTTP server.
func NewServer(cfg *config.Config, handlers *Handlers, logger *slog.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/data", handlers.DataHandler)

	return &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: mux,
	}
}
