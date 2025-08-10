package snyk

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

// APIRequest is the request body for the Snyk export API.
type APIRequest struct {
	Data RequestData `json:"data"`
}

// RequestData represents the "data" field in the Snyk API request.
type RequestData struct {
	Type       string            `json:"type"`
	Attributes RequestAttributes `json:"attributes"`
}

// RequestAttributes represents the "attributes" field in the Snyk API request.
type RequestAttributes struct {
	Formats []string       `json:"formats"`
	Columns []string       `json:"columns"`
	Dataset string         `json:"dataset"`
	Filters RequestFilters `json:"filters"`
}

// RequestFilters represents the "filters" field in the Snyk API request.
type RequestFilters struct {
	Orgs        []string         `json:"orgs"`
	Introduced  RequestDateRange `json:"introduced,omitempty"`
	Updated     RequestDateRange `json:"updated,omitempty"`
	Environment []string         `json:"environment,omitempty"`
	Lifecycle   []string         `json:"lifecycle,omitempty"`
	Severities  []string         `json:"severities,omitempty"`
}

// RequestDateRange represents a date range filter.
type RequestDateRange struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// ExportFilters holds the filtering options passed from the frontend.
type ExportFilters struct {
	IntroducedFrom      string
	IntroducedTo        string
	UpdatedFrom         string
	UpdatedTo           string
	Orgs                []string
	ProjectEnvironments []string
	ProjectLifecycles   []string
	Severities          []string
}
