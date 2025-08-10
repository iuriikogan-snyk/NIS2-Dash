package config

import (
	"os"
)

// Config holds environment-based settings.
type Config struct {
	SnykToken      string
	SnykGroupID    string
	SnykApiBaseUrl string
	Port           string
}

// NewConfig creates and returns a new Config instance from environment variables.
func NewConfig() (*Config, error) {
	cfg := &Config{
		SnykToken:      os.Getenv("SNYK_TOKEN"),
		SnykGroupID:    os.Getenv("SNYK_GROUP_ID"),
		SnykApiBaseUrl: getEnv("SNYK_API_BASE_URL", "https://api.snyk.io"),
		Port:           getEnv("PORT", "8080"),
	}
	// Basic validation can be added here if needed
	return cfg, nil
}

// getEnv returns env var value or fallback.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
