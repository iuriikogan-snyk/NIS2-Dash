package main

import (
	"errors"
	"log/slog"
	"net/http"
	"os"

	"github.com/iuriikogan-snyk/NIS2-Dash/backend/internal/config"
	"github.com/iuriikogan-snyk/NIS2-Dash/backend/internal/processor"
	"github.com/iuriikogan-snyk/NIS2-Dash/backend/internal/server"
	"github.com/iuriikogan-snyk/NIS2-Dash/backend/internal/snyk"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))

	cfg, err := config.NewConfig()
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	if cfg.SnykToken == "" || cfg.SnykGroupID == "" {
		logger.Error("SNYK_TOKEN and SNYK_GROUP_ID must be set")
		os.Exit(1)
	}

	snykClient := snyk.NewClient(cfg, logger)
	csvProcessor := processor.NewCSVProcessor(logger)
	handlers := server.NewHandlers(logger, snykClient, csvProcessor)

	srv := server.NewServer(cfg, handlers, logger)

	logger.Info("Backend server starting", "port", cfg.Port, "snyk_api_url", cfg.SnykApiBaseUrl)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
