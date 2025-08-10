package processor

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/iuriikogan-snyk/NIS2-Dash/backend/internal/snyk"
)

// CSVProcessor handles processing of Snyk CSV export data.
type CSVProcessor struct {
	logger     *slog.Logger
	httpClient *http.Client
}

// NewCSVProcessor creates a new CSV processor.
func NewCSVProcessor(logger *slog.Logger) *CSVProcessor {
	return &CSVProcessor{
		logger:     logger,
		httpClient: &http.Client{},
	}
}

// FetchAndProcessCSV downloads and aggregates the CSV export into dashboard data.
func (p *CSVProcessor) FetchAndProcessCSV(ctx context.Context, fileURL string) (*snyk.DashboardData, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)
	return p.ProcessCSV(ctx, reader)
}

func (p *CSVProcessor) ProcessCSV(ctx context.Context, reader *csv.Reader) (*snyk.DashboardData, error) {
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	colIndex := make(map[string]int)
	for i, col := range header {
		colIndex[col] = i
	}

	severityCol, hasSeverity := colIndex["ISSUE_SEVERITY"]
	fixabilityCol, hasFixability := colIndex["COMPUTED_FIXABILITY"]
	envsCol, hasEnvs := colIndex["PROJECT_ENVIRONMENTS"]
	projectCol, hasProject := colIndex["PROJECT_NAME"]

	issuesBySeverity := make(map[string]int)
	issuesByEnvironment := make(map[string]int)
	issuesByProject := make(map[string]int)
	fixableCriticals := 0

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			p.logger.Warn("error reading CSV record", "error", err)
			continue
		}

		var severity, fixability, projectName, environments string

		if hasSeverity {
			severity = getColumnValue(record, severityCol)
		}
		if hasFixability {
			fixability = getColumnValue(record, fixabilityCol)
		}
		if hasProject {
			projectName = getColumnValue(record, projectCol)
		}
		if hasEnvs {
			environments = getColumnValue(record, envsCol)
		} else {
			environments = "N/A"
		}

		if severity != "" {
			issuesBySeverity[severity]++
		} else {
			issuesBySeverity["unknown"]++
		}

		if projectName != "" {
			issuesByProject[projectName]++
		}

		envs := splitAndClean(environments)
		if len(envs) > 0 {
			for _, env := range envs {
				issuesByEnvironment[env]++
			}
		} else {
			issuesByEnvironment["N/A"]++
		}

		if severity == "critical" && fixability == "fixable" {
			fixableCriticals++
		}
	}

	// Note: Top5RiskiestProjects logic has been simplified for now.
	return &snyk.DashboardData{
		IssuesBySeverity:      issuesBySeverity,
		IssuesByEnvironment:   issuesByEnvironment,
		FixableCriticalIssues: fixableCriticals,
		Top5RiskiestProjects:  []snyk.ProjectInfo{},
	}, nil
}

func getColumnValue(record []string, index int) string {
	if index >= 0 && index < len(record) {
		return record[index]
	}
	return ""
}

func splitAndClean(s string) []string {
	if s == "" || s == "N/A" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
