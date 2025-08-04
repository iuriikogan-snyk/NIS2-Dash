package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"time"
)

//
// main.go is the entry point for the NIS2-Dash backend application.
// It initializes the application, sets up the /api/data route, and starts the HTTP server.
// The handler for /api/data orchestrates the Snyk export workflow: initiating the export,
// polling for completion, and processing the resulting CSV data into aggregated metrics.
//

// Config holds application configuration loaded from the environment.
type Config struct {
	SnykToken string
	SnykOrgID string
	Port      string
}

// App encapsulates application properties and dependencies.
type App struct {
	config     Config
	logger     *slog.Logger
	httpClient *http.Client
}

// ProjectInfo holds aggregated risk data for a single Snyk project.
type ProjectInfo struct {
	Name               string `json:"name"`
	CriticalIssueCount int    `json:"criticalIssueCount"`
	HighIssueCount     int    `json:"highIssueCount"`
}

// DashboardData is the structure of the JSON response sent to the frontend.
type DashboardData struct {
	IssuesBySeverity      map[string]int `json:"issuesBySeverity"`
	IssuesByEnvironment   map[string]int `json:"issuesByEnvironment"`
	FixableCriticalIssues int            `json:"fixableCriticalIssues"`
	Top5RiskiestProjects  []ProjectInfo  `json:"top5RiskiestProjects"`
}

// NewApp creates a new App instance with its dependencies.
func NewApp(cfg Config, logger *slog.Logger) *App {
	return &App{
		config:     cfg,
		logger:     logger,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// main is the application entry point.
func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg := Config{
		SnykToken: os.Getenv("SNYK_TOKEN"),
		SnykOrgID: os.Getenv("SNYK_ORG_ID"),
		Port:      getEnv("PORT", "8080"), // Use helper to set default port
	}
	if cfg.SnykToken == "" || cfg.SnykOrgID == "" {
		logger.Error("SNYK_TOKEN and SNYK_ORG_ID must be set")
		os.Exit(1)
	}

	app := NewApp(cfg, logger) // Correctly initialize the App struct

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/data", app.dataHandler) // Use the initialized app variable

	logger.Info("Backend server starting", "port", cfg.Port)
	server := &http.Server{Addr: ":" + cfg.Port, Handler: mux}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}

// dataHandler orchestrates the Snyk export and data processing workflow.
func (a *App) dataHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a.logger.Info("Starting Snyk analytics export for enhanced metrics...")

	exportID, err := a.initiateExport(ctx)
	if err != nil {
		a.logger.Error("Failed to initiate export", "error", err)
		http.Error(w, "Failed to initiate Snyk export", http.StatusInternalServerError)
		return
	}

	fileURL, err := a.pollExportStatus(ctx, exportID)
	if err != nil {
		a.logger.Error("Failed to get finished export status", "error", err)
		http.Error(w, "Failed to complete Snyk export", http.StatusInternalServerError)
		return
	}

	dashboardData, err := a.fetchAndProcessCSV(ctx, fileURL)
	if err != nil {
		a.logger.Error("Failed to process CSV data", "error", err)
		http.Error(w, "Failed to process exported Snyk data", http.StatusInternalServerError)
		return
	}

	a.respondWithJSON(w, http.StatusOK, dashboardData)
}

// initiateExport sends a request to Snyk to start a new data export job.
func (a *App) initiateExport(ctx context.Context) (string, error) {
	type InitiateExportRequest struct {
		Filters struct {
			Orgs []string `json:"orgs"`
		} `json:"filters"`
		Columns []string `json:"columns"`
	}
	reqBody := InitiateExportRequest{
		Columns: []string{"issue_severity", "issue_type", "project_environments", "computed_fixability", "project_name"},
	}
	reqBody.Filters.Orgs = []string{a.config.SnykOrgID}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	url := fmt.Sprintf("https://api.snyk.io/v1/org/%s/exports?version=2024-10-15", a.config.SnykOrgID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "", err
	}
	a.setAuthHeader(req)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	type InitiateExportResponse struct {
		ExportID string `json:"export_id"`
	}
	var exportResp InitiateExportResponse
	if err := json.NewDecoder(resp.Body).Decode(&exportResp); err != nil {
		return "", err
	}

	return exportResp.ExportID, nil
}

// pollExportStatus periodically checks the status of an export job until it is complete.
func (a *App) pollExportStatus(ctx context.Context, exportID string) (string, error) {
	type ExportStatusResponse struct {
		Status  string `json:"status"`
		Results struct {
			Files []struct {
				URL string `json:"url"`
			} `json:"files,omitempty"`
		} `json:"results,omitempty"`
	}

	url := fmt.Sprintf("https://api.snyk.io/v1/org/%s/exports/%s?version=2024-10-15", a.config.SnykOrgID, exportID)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	pollingCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	for {
		select {
		case <-pollingCtx.Done():
			return "", errors.New("polling timed out after 2 minutes")
		case <-ticker.C:
			req, _ := http.NewRequestWithContext(pollingCtx, "GET", url, nil)
			a.setAuthHeader(req)
			resp, err := a.httpClient.Do(req)
			if err != nil {
				a.logger.Warn("Polling check failed", "error", err)
				continue
			}
			var statusResp ExportStatusResponse
			if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
				resp.Body.Close()
				a.logger.Warn("Failed to decode status response", "error", err)
				continue
			}
			resp.Body.Close()

			if statusResp.Status == "FINISHED" {
				if len(statusResp.Results.Files) > 0 {
					return statusResp.Results.Files[0].URL, nil
				}
				return "", errors.New("export finished but no file URL was provided")
			}
			if statusResp.Status == "ERROR" {
				return "", errors.New("export job failed with ERROR status")
			}
		}
	}
}

// fetchAndProcessCSV downloads the exported data and aggregates it into the DashboardData structure.
func (a *App) fetchAndProcessCSV(ctx context.Context, fileURL string) (*DashboardData, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}

	colIndex := make(map[string]int)
	for i, colName := range header {
		colIndex[colName] = i
	}

	issuesBySeverity, issuesByEnvironment := make(map[string]int), make(map[string]int)
	fixableCriticals, projectIssues := 0, make(map[string]*ProjectInfo)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		severity := record[colIndex["issue_severity"]]
		projectName := record[colIndex["project_name"]]

		if severity != "" {
			issuesBySeverity[severity]++
		}

		if envs := record[colIndex["project_environments"]]; envs != "" {
			issuesByEnvironment[envs]++
		} else {
			issuesByEnvironment["undefined"]++
		}

		if severity == "critical" && record[colIndex["computed_fixability"]] == "fixable" {
			fixableCriticals++
		}

		if _, ok := projectIssues[projectName]; !ok {
			projectIssues[projectName] = &ProjectInfo{Name: projectName}
		}
		if severity == "critical" {
			projectIssues[projectName].CriticalIssueCount++
		}
		if severity == "high" {
			projectIssues[projectName].HighIssueCount++
		}
	}

	var projects []ProjectInfo
	for _, proj := range projectIssues {
		projects = append(projects, *proj)
	}
	sort.Slice(projects, func(i, j int) bool {
		if projects[i].CriticalIssueCount != projects[j].CriticalIssueCount {
			return projects[i].CriticalIssueCount > projects[j].CriticalIssueCount
		}
		return projects[i].HighIssueCount > projects[j].HighIssueCount
	})

	top5Projects := projects
	if len(projects) > 5 {
		top5Projects = projects[:5]
	}

	return &DashboardData{
		IssuesBySeverity:      issuesBySeverity,
		IssuesByEnvironment:   issuesByEnvironment,
		FixableCriticalIssues: fixableCriticals,
		Top5RiskiestProjects:  top5Projects,
	}, nil
}

// setAuthHeader adds required headers for Snyk API requests.
func (a *App) setAuthHeader(r *http.Request) {
	r.Header.Set("Authorization", "token "+a.config.SnykToken)
	r.Header.Set("Content-Type", "application/json")
}

// respondWithJSON is a helper to write JSON responses.
func (a *App) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(response)
}

// getEnv reads an environment variable or returns a default value.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
