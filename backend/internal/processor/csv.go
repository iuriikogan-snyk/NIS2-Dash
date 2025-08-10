package processor

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
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
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}

	colIndex := make(map[string]int)
	for i, colName := range header {
		colIndex[colName] = i
	}

	severityCol, ok1 := colIndex["ISSUE_SEVERITY"]
	fixabilityCol, ok2 := colIndex["AUTOFIXABLE"]
	envsCol, ok3 := colIndex["PROJECT_ENVIRONMENTS"]
	projectCol, ok4 := colIndex["PROJECT_NAME"]

	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, fmt.Errorf("missing one or more required columns in CSV: ISSUE_SEVERITY, AUTOFIXABLE, PROJECT_ENVIRONMENTS, PROJECT_NAME")
	}

	issuesBySeverity := map[string]int{}
	issuesByEnvironment := map[string]int{}
	fixableCriticals := 0
	projectIssues := map[string]*snyk.ProjectInfo{}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(record) < len(header) {
			p.logger.Warn("Skipping malformed CSV row", "error", err)
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
			projectIssues[projectName] = &snyk.ProjectInfo{Name: projectName}
		}
		if severity == "critical" {
			projectIssues[projectName].CriticalIssueCount++
		}
		if severity == "high" {
			projectIssues[projectName].HighIssueCount++
		}
	}

	var projects []snyk.ProjectInfo
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

	return &snyk.DashboardData{
		IssuesBySeverity:      issuesBySeverity,
		IssuesByEnvironment:   issuesByEnvironment,
		FixableCriticalIssues: fixableCriticals,
		Top5RiskiestProjects:  projects,
	}, nil
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
