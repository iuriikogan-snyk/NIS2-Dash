package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/iuriikogan-snyk/NIS2-Dash/backend/internal/processor"
	"github.com/iuriikogan-snyk/NIS2-Dash/backend/internal/snyk"
)

// Handlers holds dependencies for HTTP handlers.
type Handlers struct {
	logger     *slog.Logger
	snykClient *snyk.Client
	processor  *processor.CSVProcessor
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(logger *slog.Logger, snykClient *snyk.Client, processor *processor.CSVProcessor) *Handlers {
	return &Handlers{
		logger:     logger,
		snykClient: snykClient,
		processor:  processor,
	}
}

// DataHandler handles GET /api/data by exporting, polling, and processing Snyk data.
func (h *Handlers) DataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	h.logger.Info("Starting Snyk analytics exports")

	queryParams := r.URL.Query()
	orgs := splitAndClean(queryParams.Get("orgs"))

	if len(orgs) == 0 {
		h.logger.Info("No orgs specified, fetching all orgs in the group")
		fetchedOrgs, err := h.snykClient.GetOrgsInGroup(ctx)
		if err != nil {
			h.logger.Error("Failed to fetch organizations in group", "error", err.Error())
			http.Error(w, "Failed to fetch Snyk organizations", http.StatusInternalServerError)
			return
		}
		orgs = fetchedOrgs
	}

	filters := &snyk.ExportFilters{
		IntroducedFrom:      parseDateParam(queryParams.Get("introduced_from")),
		IntroducedTo:        parseDateParam(queryParams.Get("introduced_to")),
		UpdatedFrom:         parseDateParam(queryParams.Get("updated_from")),
		UpdatedTo:           parseDateParam(queryParams.Get("updated_to")),
		Orgs:                orgs,
		ProjectEnvironments: splitAndClean(queryParams.Get("env")),
		ProjectLifecycles:   splitAndClean(queryParams.Get("lifecycle")),
		Severities:          splitAndClean(queryParams.Get("severities")),
	}

	exportID, err := h.snykClient.InitiateExport(ctx, filters)
	if err != nil {
		h.logger.Error("Failed to initiate export", "error", err.Error())
		http.Error(w, "Failed to initiate Snyk export", http.StatusInternalServerError)
		return
	}
	h.logger.Info("Snyk export initiated", "exportID", exportID)

	fileURL, err := h.snykClient.PollExportStatus(ctx, exportID, filters.Orgs[0])
	if err != nil {
		h.logger.Error("Failed to get finished export status", "error", err.Error())
		http.Error(w, "Failed to complete Snyk export", http.StatusInternalServerError)
		return
	}
	h.logger.Info("Snyk export finished, CSV ready for download", "url", fileURL)

	dashboardData, err := h.processor.FetchAndProcessCSV(ctx, fileURL)
	if err != nil {
		h.logger.Error("Failed to process CSV data", "error", err.Error())
		http.Error(w, "Failed to process exported Snyk data", http.StatusInternalServerError)
		return
	}

	respondWithJSON(w, http.StatusOK, dashboardData)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(response)
}

func parseDateParam(dateStr string) string {
	if dateStr == "" {
		return ""
	}
	if days, err := strconv.Atoi(dateStr); err == nil {
		return time.Now().UTC().AddDate(0, 0, days).Format("2006-01-02T00:00:00Z")
	}
	return dateStr
}

func splitAndClean(input string) []string {
	if input == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
