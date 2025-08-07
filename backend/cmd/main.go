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
	SnykToken      string
	SnykGroupID    string
	SnykApiBaseUrl string // Added to support different Snyk regions (e.g., EU, AU)
	Port           string
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
	Orgs                []string         `json:"orgs"`
	Introduced          RequestDateRange `json:"introduced,omitempty"`
	Updated             RequestDateRange `json:"updated,omitempty"`
	ProjectEnvironments []string         `json:"project_environment,omitempty"`
	ProjectLifecycles   []string         `json:"project_lifecycle,omitempty"`
	Severities          []string         `json:"severities,omitempty"`
}

// RequestDateRange represents a date range filter.
type RequestDateRange struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// SnykExportFilters holds the filtering options passed from the frontend.
type SnykExportFilters struct {
	IntroducedFrom      string
	IntroducedTo        string
	UpdatedFrom         string
	UpdatedTo           string
	Orgs                []string
	ProjectEnvironments []string
	ProjectLifecycles   []string
	Severities          []string
}

// NewApp creates and returns a new App instance.
func NewApp(cfg Config, logger *slog.Logger) *App {
	return &App{
		config:     cfg,
		logger:     logger,
		httpClient: &http.Client{Timeout: 60 * time.Second}, // Increased timeout for potentially long-running requests
	}
}

// main is the entry point of the application.
func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))
	cfg := Config{
		SnykToken:      os.Getenv("SNYK_TOKEN"),
		SnykGroupID:    os.Getenv("SNYK_GROUP_ID"),
		SnykApiBaseUrl: getEnv("SNYK_API_BASE_URL", "https://api.snyk.io"), // Make base URL configurable
		Port:           getEnv("PORT", "8080"),
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
	logger.Info("Backend server starting", "port", cfg.Port, "snyk_api_url", cfg.SnykApiBaseUrl)
	server := &http.Server{Addr: ":" + cfg.Port, Handler: mux}
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}

// dataHandler handles GET /api/data by exporting, polling, and processing Snyk data.
func (a *App) dataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()
	a.logger.Info("Starting Snyk analytics exports")

	// Parse filters from URL query parameters
	queryParams := r.URL.Query()
	orgs := splitAndClean(queryParams.Get("orgs"))

	// If no orgs are specified in the query, fetch all orgs from the group
	if len(orgs) == 0 {
		a.logger.Info("No orgs specified, fetching all orgs in the group")
		fetchedOrgs, err := a.getOrgsInGroup(ctx)
		if err != nil {
			a.logger.Error("Failed to fetch organizations in group", "error", err.Error())
			http.Error(w, "Failed to fetch Snyk organizations", http.StatusInternalServerError)
			return
		}
		orgs = fetchedOrgs
	}

	filters := &SnykExportFilters{
		IntroducedFrom:      parseDateParam(queryParams.Get("introduced_from")),
		IntroducedTo:        parseDateParam(queryParams.Get("introduced_to")),
		UpdatedFrom:         parseDateParam(queryParams.Get("updated_from")),
		UpdatedTo:           parseDateParam(queryParams.Get("updated_to")),
		Orgs:                orgs,
		ProjectEnvironments: splitAndClean(queryParams.Get("env")),
		ProjectLifecycles:   splitAndClean(queryParams.Get("lifecycle")),
		Severities:          splitAndClean(queryParams.Get("severities")),
	}

	exportID, err := a.initiateExport(ctx, filters)
	if err != nil {
		a.logger.Error("Failed to initiate export", "error", err.Error())
		http.Error(w, "Failed to initiate Snyk export", http.StatusInternalServerError)
		return
	}
	a.logger.Info("Snyk export initiated", "exportID", exportID)

	fileURL, err := a.pollExportStatus(ctx, exportID)
	if err != nil {
		a.logger.Error("Failed to get finished export status", "error", err.Error())
		http.Error(w, "Failed to complete Snyk export", http.StatusInternalServerError)
		return
	}
	a.logger.Info("Snyk export finished, CSV ready for download", "url", fileURL)

	dashboardData, err := a.fetchAndProcessCSV(ctx, fileURL)
	if err != nil {
		a.logger.Error("Failed to process CSV data", "error", err.Error())
		http.Error(w, "Failed to process exported Snyk data", http.StatusInternalServerError)
		return
	}

	a.respondWithJSON(w, http.StatusOK, dashboardData)
}

// getOrgsInGroup fetches all organization IDs for the configured Snyk group.
func (a *App) getOrgsInGroup(ctx context.Context) ([]string, error) {
	var allOrgIDs []string
	// Use a recent, stable API version for listing organizations.
	url := fmt.Sprintf("%s/rest/groups/%s/orgs?version=2024-07-29&limit=100", a.config.SnykApiBaseUrl, a.config.SnykGroupID)

	type OrgListResponse struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Links struct {
			Next string `json:"next,omitempty"`
		} `json:"links"`
	}

	for url != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request to fetch orgs: %w", err)
		}
		a.setAuthHeader(req)

		resp, err := a.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request to fetch orgs failed: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("failed to fetch orgs, Snyk API returned status %d: %s", resp.StatusCode, string(body))
		}

		var orgResp OrgListResponse
		if err := json.NewDecoder(resp.Body).Decode(&orgResp); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode orgs response: %w", err)
		}
		resp.Body.Close()

		for _, org := range orgResp.Data {
			allOrgIDs = append(allOrgIDs, org.ID)
		}

		// Handle pagination
		if orgResp.Links.Next != "" {
			url = fmt.Sprintf("%s%s", a.config.SnykApiBaseUrl, orgResp.Links.Next)
		} else {
			url = ""
		}
	}

	return allOrgIDs, nil
}

// initiateExport starts a new Snyk export job and returns the export ID.
func (a *App) initiateExport(ctx context.Context, filters *SnykExportFilters) (string, error) {
	reqBody := SnykAPIRequest{
		Data: RequestData{
			Type: "export",
			Attributes: RequestAttributes{
				Formats: []string{"csv"},
				Columns: []string{
					"ISSUE_SEVERITY",
					"SCORE",
					"CVE",
					"CWE",
					"ORG_DISPLAY_NAME",
					"PROJECT_NAME",
					"PROJECT_URL",
					"EXPLOIT_MATURITY",
					"COMPUTED_FIXABILITY",
					"FIRST_INTRODUCED",
					"PRODUCT_NAME",
					"ISSUE_URL",
					"ISSUE_STATUS_INDICATOR",
					"ISSUE_TYPE",
					"PROJECT_ENVIRONMENTS",
				},
				Dataset: "issues",
				Destination: RequestDestination{
					Type: "snyk",
				},
				Filters: RequestFilters{
					Orgs:                filters.Orgs,
					Introduced:          RequestDateRange{From: filters.IntroducedFrom, To: filters.IntroducedTo},
					Updated:             RequestDateRange{From: filters.UpdatedFrom, To: filters.UpdatedTo},
					ProjectEnvironments: filters.ProjectEnvironments,
					ProjectLifecycles:   filters.ProjectLifecycles,
					Severities:          filters.Severities,
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	url := fmt.Sprintf("%s/rest/groups/%s/exports?version=2024-10-15", a.config.SnykApiBaseUrl, a.config.SnykGroupID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "", err
	}
	a.setAuthHeader(req)
	req.Header.Set("Content-Type", "application/vnd.api+json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Snyk API returned status %d: %s", resp.StatusCode, string(body))
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

// pollExportStatus polls the export job until it's complete, then returns the download URL.
func (a *App) pollExportStatus(ctx context.Context, exportID string) (string, error) {
	url := fmt.Sprintf("%s/rest/groups/%s/exports/%s?version=2024-10-15", a.config.SnykApiBaseUrl, a.config.SnykGroupID, exportID)

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
	pollingCtx, cancel := context.WithTimeout(ctx, 5*time.Minute) // Increased timeout for long exports
	defer cancel()

	a.logger.Info("Polling for export completion...", "exportID", exportID)
	for {
		select {
		case <-pollingCtx.Done():
			return "", errors.New("polling timed out after 5 minutes")
		case <-ticker.C:
			req, _ := http.NewRequestWithContext(pollingCtx, "GET", url, nil)
			a.setAuthHeader(req)

			resp, err := a.httpClient.Do(req)
			if err != nil {
				a.logger.Warn("Polling request failed", "error", err.Error())
				continue
			}

			if resp.StatusCode != http.StatusOK {
				a.logger.Warn("Polling received non-200 status", "status", resp.Status)
				resp.Body.Close()
				continue
			}

			var statusResp ExportStatusResponse
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				resp.Body.Close()
				a.logger.Warn("Failed to read polling response body", "error", err)
				continue
			}
			resp.Body.Close()

			if err := json.Unmarshal(bodyBytes, &statusResp); err != nil {
				a.logger.Warn("Invalid JSON in polling response", "error", err.Error())
				continue
			}

			a.logger.Info("Polling status check", "status", statusResp.Data.Attributes.Status)
			switch statusResp.Data.Attributes.Status {
			case "FINISHED":
				if len(statusResp.Data.Attributes.Results.Files) > 0 {
					return statusResp.Data.Attributes.Results.Files[0].URL, nil
				}
				return "", errors.New("export finished but no file URL was provided")
			case "ERROR":
				return "", errors.New("export job failed with ERROR status")
			}
		}
	}
}

// fetchAndProcessCSV downloads and aggregates the CSV export into dashboard data.
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

	severityCol, ok1 := colIndex["ISSUE_SEVERITY"]
	fixabilityCol, ok2 := colIndex["COMPUTED_FIXABILITY"]
	envsCol, ok3 := colIndex["PROJECT_ENVIRONMENTS"]
	projectCol, ok4 := colIndex["PROJECT_NAME"]

	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, fmt.Errorf("missing one or more required columns in CSV: ISSUE_SEVERITY, COMPUTED_FIXABILITY, PROJECT_ENVIRONMENTS, PROJECT_NAME")
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
			a.logger.Warn("Skipping malformed CSV row", "error", err)
			continue
		}

		severity := record[severityCol]
		projectName := record[projectCol]
		envs := record[envsCol]
		fixability := record[fixabilityCol]

		if severity != "" {
			issuesBySeverity[severity]++
		}
		if envs != "" {
			for _, env := range splitAndClean(envs) {
				issuesByEnvironment[env]++
			}
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
	if days, err := strconv.Atoi(dateStr); err == nil {
		return time.Now().UTC().AddDate(0, 0, days).Format("2006-01-02T00:00:00Z")
	}
	return dateStr
}

// respondWithJSON sends a JSON response to the client.
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

// getEnv returns env var value or fallback.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
