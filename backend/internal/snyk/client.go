package snyk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/iuriikogan-snyk/NIS2-Dash/backend/internal/config"
)

// Client handles communication with the Snyk API.
type Client struct {
	config     *config.Config
	logger     *slog.Logger
	httpClient *http.Client
}

// NewClient creates a new Snyk API client.
func NewClient(cfg *config.Config, logger *slog.Logger) *Client {
	return &Client{
		config:     cfg,
		logger:     logger,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Client) setAuthHeader(r *http.Request) {
	if r == nil {
		return
	}
	r.Header.Set("Authorization", "token "+c.config.SnykToken)
}

// GetOrgsInGroup fetches all organization IDs for the configured Snyk group.
func (c *Client) GetOrgsInGroup(ctx context.Context) ([]string, error) {
	var allOrgIDs []string
	url := fmt.Sprintf("%s/rest/groups/%s/orgs?version=2024-07-29&limit=100", c.config.SnykApiBaseUrl, c.config.SnykGroupID)

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
		c.setAuthHeader(req)

		resp, err := c.httpClient.Do(req)
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

		if orgResp.Links.Next != "" {
			url = fmt.Sprintf("%s%s", c.config.SnykApiBaseUrl, orgResp.Links.Next)
		} else {
			url = ""
		}
	}

	return allOrgIDs, nil
}

// InitiateExport starts a new Snyk export job and returns the export ID.
func (c *Client) InitiateExport(ctx context.Context, filters *ExportFilters) (string, error) {
	if len(filters.Orgs) == 0 {
		return "", fmt.Errorf("no organizations specified for export")
	}

	orgID := filters.Orgs[0]

	reqBody := APIRequest{
		Data: RequestData{
			Type: "resource",
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
					"AUTOFIXABLE",
					"FIRST_INTRODUCED",
					"PRODUCT_NAME",
					"ISSUE_URL",
					"ISSUE_STATUS_INDICATOR",
					"ISSUE_TYPE",
					"PROJECT_ENVIRONMENTS",
				},
				Dataset: "issues",
				Filters: RequestFilters{
					Introduced:  RequestDateRange{From: filters.IntroducedFrom, To: filters.IntroducedTo},
					Updated:     RequestDateRange{From: filters.UpdatedFrom, To: filters.UpdatedTo},
					Environment: filters.ProjectEnvironments,
					Lifecycle:   filters.ProjectLifecycles,
					Severities:  filters.Severities,
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	url := fmt.Sprintf("%s/rest/orgs/%s/export?version=2024-10-15", c.config.SnykApiBaseUrl, orgID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "", err
	}
	c.setAuthHeader(req)
	req.Header.Set("Content-Type", "application/vnd.api+json")

	resp, err := c.httpClient.Do(req)
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

// PollExportStatus polls the export job until it's complete, then returns the download URL.
func (c *Client) PollExportStatus(ctx context.Context, exportID string, orgID string) (string, error) {
	statusURL := fmt.Sprintf("%s/rest/orgs/%s/jobs/export/%s?version=2024-10-15", c.config.SnykApiBaseUrl, orgID, exportID)
	resultsURL := fmt.Sprintf("%s/rest/orgs/%s/export/%s?version=2024-10-15", c.config.SnykApiBaseUrl, orgID, exportID)

	type ExportStatusResponse struct {
		Data struct {
			Attributes struct {
				Status  string `json:"status"`
				Results []struct {
					URL string `json:"url"`
				} `json:"results,omitempty"`
			} `json:"attributes"`
		} `json:"data"`
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	pollingCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	c.logger.Info("Polling for export completion...", "exportID", exportID)
	for {
		select {
		case <-pollingCtx.Done():
			return "", errors.New("polling timed out after 5 minutes")
		case <-ticker.C:
			req, _ := http.NewRequestWithContext(pollingCtx, "GET", statusURL, nil)
			c.setAuthHeader(req)

			resp, err := c.httpClient.Do(req)
			if err != nil {
				c.logger.Warn("Polling request failed", "error", err.Error())
				continue
			}

			if resp.StatusCode != http.StatusOK {
				c.logger.Warn("Polling received non-200 status", "status", resp.Status)
				resp.Body.Close()
				continue
			}

			var statusResp ExportStatusResponse
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				resp.Body.Close()
				c.logger.Warn("Failed to read polling response body", "error", err)
				continue
			}
			resp.Body.Close()

			if err := json.Unmarshal(bodyBytes, &statusResp); err != nil {
				c.logger.Warn("Invalid JSON in polling response", "error", err.Error())
				continue
			}

			c.logger.Info("Polling status check", "status", statusResp.Data.Attributes.Status)
			switch statusResp.Data.Attributes.Status {
			case "FINISHED":
				req, _ := http.NewRequestWithContext(pollingCtx, "GET", resultsURL, nil)
				c.setAuthHeader(req)

				resp, err := c.httpClient.Do(req)
				if err != nil {
					c.logger.Warn("Results request failed", "error", err.Error())
					continue
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					c.logger.Warn("Results received non-200 status", "status", resp.Status)
					continue
				}

				var resultsResp ExportStatusResponse
				if err := json.NewDecoder(resp.Body).Decode(&resultsResp); err != nil {
					c.logger.Warn("Invalid JSON in results response", "error", err.Error())
					continue
				}

				if len(resultsResp.Data.Attributes.Results) > 0 {
					return resultsResp.Data.Attributes.Results[0].URL, nil
				}
				return "", errors.New("export finished but no file URL was provided")
			case "ERROR":
				return "", errors.New("export job failed with ERROR status")
			}
		}
	}
}
