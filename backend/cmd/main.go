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
	"strconv"
	"strings"
	"time"
)

//
// main.go is the entry point for the NIS2-Dash backend application.
// It initializes the application, sets up the /api/data route, and starts the HTTP server.
// The handler for /api/data orchestrates the Snyk export workflow: initiating the export,
// polling for completion, and processing the resulting CSV data into aggregated metrics.
//

// Config holds environment-based settings.
type Config struct {
	SnykToken   string
	SnykGroupID string
	Port        string
}

// App holds app-wide dependencies.
type App struct {
	config     Config
	logger     *slog.Logger
	httpClient *http.Client
}

// ProjectInfo holds risk data per project.
type ProjectInfo struct {
	Name               string `json:"name"`
	CriticalIssueCount int    `json:"criticalIssueCount"`
	HighIssueCount     int    `json:"highIssueCount"`
}

// DashboardData is returned as JSON to the frontend.
type DashboardData struct {
	IssuesBySeverity      map[string]int `json:"issuesBySeverity"`
	IssuesByEnvironment   map[string]int `json:"issuesByEnvironment"`
	FixableCriticalIssues int            `json:"fixableCriticalIssues"`
	Top5RiskiestProjects  []ProjectInfo  `json:"top5RiskiestProjects"`
}

// SnykAPIRequest is the request body for the Snyk export API.
type SnykAPIRequest struct {
	Data RequestData `json:"data"`
}

// RequestData represents the "data" field in the Snyk API request.
type RequestData struct {
	Type       string            `json:"type"`
	Attributes RequestAttributes `json:"attributes"`
}

// RequestAttributes represents the "attributes" field in the Snyk API request.
type RequestAttributes struct {
	Formats     []string           `json:"formats"`
	Columns     []string           `json:"columns"`
	Dataset     string             `json:"dataset"`
	Destination RequestDestination `json:"destination"`
	Filters     RequestFilters     `json:"filters"`
}

// RequestDestination represents the "destination" field in the Snyk API request.
type RequestDestination struct {
	Type string `json:"type"`
}

// RequestFilters represents the "filters" field in the Snyk API request.
type RequestFilters struct {
	Orgs       []string          `json:"orgs"`
	Introduced RequestIntroduced `json:"introduced"`
}

// RequestIntroduced represents the "introduced" filter.
type RequestIntroduced struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// SnykExportFilters holds the filtering options passed from the frontend.
type SnykExportFilters struct {
	IntroducedFrom string
	IntroducedTo   string
	Orgs           []string
}

// Creates and returns a new App instance.
func NewApp(cfg Config, logger *slog.Logger) *App {
	return &App{
		config:     cfg,
		logger:     logger,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Entry point of the application.
func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))
	cfg := Config{
		SnykToken:   os.Getenv("SNYK_TOKEN"),
		SnykGroupID: os.Getenv("SNYK_GROUP_ID"),
		Port:        getEnv("PORT", "8080"),
	}
	if cfg.SnykToken == "" || cfg.SnykGroupID == "" {
		logger.Error("SNYK_TOKEN and SNYK_GROUP_ID must be set")
		os.Exit(1)
	}

	app := NewApp(cfg, logger)

	// Register route
	mux := http.NewServeMux()
	mux.HandleFunc("/api/data", app.dataHandler)

	// Start HTTP server
	logger.Info("Backend server starting", "port", cfg.Port)
	server := &http.Server{Addr: ":" + cfg.Port, Handler: mux}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}

// Handles GET /api/data by exporting, polling, and processing Snyk data.
func (a *App) dataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	a.logger.Info("Starting Snyk analytics exports")

	queryParams := r.URL.Query()
	filters := &SnykExportFilters{
		IntroducedFrom: parseDateParam(queryParams.Get("introduced_from")),
		IntroducedTo:   parseDateParam(queryParams.Get("introduced_to")),
		Orgs:           splitAndClean(queryParams.Get("orgs")),
	}

	exportID, err := a.initiateExport(ctx, filters)
	if err != nil {
		a.logger.Error("Failed to initiate export", "error", err.Error())
		http.Error(w, "Failed to initiate Snyk export", http.StatusInternalServerError)
		return
	}

	fileURL, err := a.pollExportStatus(ctx, exportID)
	if err != nil {
		a.logger.Error("Failed to get finished export status", "error", err.Error())
		http.Error(w, "Failed to complete Snyk export", http.StatusInternalServerError)
		return
	}

	dashboardData, err := a.fetchAndProcessCSV(ctx, fileURL)
	if err != nil {
		a.logger.Error("Failed to process CSV data", "error", err.Error())
		http.Error(w, "Failed to process exported Snyk data", http.StatusInternalServerError)
		return
	}

	a.respondWithJSON(w, http.StatusOK, dashboardData)
}

// Starts a new Snyk export job and returns the export ID.
func (a *App) initiateExport(ctx context.Context, filters *SnykExportFilters) (string, error) {
	reqBody := SnykAPIRequest{
		Data: RequestData{
			Type: "resource",
			Attributes: RequestAttributes{
				Formats: []string{"csv"},
				Columns: []string{
					"issue_severity_rank", "issue_severity", "score", "problem_title", "cve", "cwe",
					"project_name", "project_url", "exploit_maturity", "first_introduced",
					"product_name", "issue_url", "issue_type", "computed_fixability", "project_environments",
				},
				Dataset: "issues",
				Destination: RequestDestination{
					Type: "snyk",
				},
				Filters: RequestFilters{
					Orgs: filters.Orgs,
					Introduced: RequestIntroduced{
						From: filters.IntroducedFrom,
						To:   filters.IntroducedTo,
					},
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	url := fmt.Sprintf("https://api.snyk.io/rest/groups/%s/exports?version=2024-10-15", a.config.SnykGroupID)
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

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Snyk API returned %d: %s", resp.StatusCode, string(body))
	}

	var exportResp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&exportResp); err != nil {
		return "", err
	}

	return exportResp.Data.ID, nil
}

// Polls the export job until it's complete, then returns the download URL.
func (a *App) pollExportStatus(ctx context.Context, exportID string) (string, error) {
	url := fmt.Sprintf("https://api.snyk.io/rest/groups/%s/exports/%s?version=2024-10-15", a.config.SnykGroupID, exportID)

	type ExportStatusResponse struct {
		Data struct {
			Attributes struct {
				Status  string `json:"status"`
				Results struct {
					Files []struct {
						URL string `json:"url"`
					} `json:"files,omitempty"`
				} `json:"results,omitempty"`
			} `json:"attributes"`
		} `json:"data"`
	}

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
				a.logger.Warn("Polling failed", "error", err.Error())
				continue
			}
			defer resp.Body.Close()

			var statusResp ExportStatusResponse
			if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
				a.logger.Warn("Invalid JSON in polling response", "error", err.Error())
				continue
			}

			switch statusResp.Data.Attributes.Status {
			case "FINISHED":
				if len(statusResp.Data.Attributes.Results.Files) > 0 {
					return statusResp.Data.Attributes.Results.Files[0].URL, nil
				}
				return "", errors.New("export finished but no file URL provided")
			case "ERROR":
				return "", errors.New("export job failed with ERROR status")
			}
		}
	}
}

// Downloads and aggregates the CSV export into dashboard data.
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

	requiredCols := []string{"issue_severity", "computed_fixability", "project_environments", "project_name"}
	for _, col := range requiredCols {
		if _, ok := colIndex[col]; !ok {
			return nil, fmt.Errorf("missing required column: %s", col)
		}
	}

	issuesBySeverity := map[string]int{}
	issuesByEnvironment := map[string]int{}
	fixableCriticals := 0
	projectIssues := map[string]*ProjectInfo{}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) < len(header) {
			continue
		}

		severity := record[colIndex["issue_severity"]]
		projectName := record[colIndex["project_name"]]
		envs := record[colIndex["project_environments"]]
		fixability := record[colIndex["computed_fixability"]]

		if severity != "" {
			issuesBySeverity[severity]++
		}
		if envs != "" {
			issuesByEnvironment[envs]++
		} else {
			issuesByEnvironment["undefined"]++
		}
		if severity == "critical" && fixability == "fixable" {
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

	if len(projects) > 5 {
		projects = projects[:5]
	}

	return &DashboardData{
		IssuesBySeverity:      issuesBySeverity,
		IssuesByEnvironment:   issuesByEnvironment,
		FixableCriticalIssues: fixableCriticals,
		Top5RiskiestProjects:  projects,
	}, nil
}

// setAuthHeader adds the authorization header to the Snyk request.
func (a *App) setAuthHeader(r *http.Request) {
	if r == nil {
		return
	}
	r.Header.Set("Authorization", "token "+a.config.SnykToken)
}

// splitAndClean takes a comma-separated string, splits it, and trims whitespace.
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

// parseDateParam converts a string into a date string for the Snyk API.
// It can be an integer for relative days, or a pre-formatted date string.
func parseDateParam(dateStr string) string {
	if dateStr == "" {
		return ""
	}
	// Try to parse as integer offset (number of days from now)
	if days, err := strconv.Atoi(dateStr); err == nil {
		return time.Now().UTC().AddDate(0, 0, days).Format("2006-01-02T00:00:00Z")
	}
	// Otherwise, assume it's already a formatted date string
	return dateStr
}

// Sends a JSON response to the client.
func (a *App) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(response)
}

// Returns env var value or fallback.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
