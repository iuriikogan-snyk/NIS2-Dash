# NIS2-Dash

Demo of how Snyk Analytics Export API can be used to consume data and publish it to a centralized compliance dashboard, specifically, NIS2 compliance

## Overview

A demonstration application showcasing Snyk's Analytics Export API capabilities for NIS2 compliance reporting. This project illustrates how organizations can leverage Snyk's export functionality to create centralized security dashboards that meet regulatory compliance requirements.

## Architecture

- **Backend**: Go-based API server that interfaces with Snyk's Analytics Export API
- **Frontend**: React-based dashboard for visualizing security metrics and compliance data

## Key Features

- **Automated Data Export**: Seamless integration with Snyk Analytics Export API
- **Flexible Filtering**: Support for date ranges, environments, lifecycles, and severity levels
- **Real-time Processing**: Automatic polling and processing of export jobs
- **Compliance Dashboard**: Visual representation of security posture for NIS2 requirements
- **Multi-Organization Support**: Handle data across multiple Snyk organizations

## Prerequisites

- **Docker & Docker Compose**: Required for containerized deployment
- **Snyk Account**: Active Snyk account with API access
- **Group Admin Access**: Permissions to access Snyk Analytics Export API
- **Node.js 20+**: For local frontend development (optional)
- **Go 1.23+**: For local backend development (optional)

## Quick Start

1. **Environment Setup**

   ```bash
   cp example.env .env
   # Configure SNYK_TOKEN and SNYK_GROUP_ID
   ```

2. **Run with Docker Compose**

   ```bash
   docker-compose up --build
   ```

3. **Access Dashboard**
   Navigate to `http://localhost:3000`

## API Endpoints

- `GET /api/data` - Retrieve filtered security data with optional query parameters:
  - `orgs` - Organization IDs
  - `introduced_from/to` - Issue introduction date range
  - `updated_from/to` - Issue update date range
  - `env` - Project environments
  - `lifecycle` - Project lifecycles
  - `severities` - Issue severity levels

## Use Cases

- **Compliance Reporting**: Generate NIS2-compliant security reports
- **Executive Dashboards**: High-level security metrics visualization
- **Risk Assessment**: Comprehensive vulnerability analysis across organizations
- **Trend Analysis**: Historical security posture tracking

## Demo Scenarios

Perfect for demonstrating to clients how Snyk's Analytics Export API can:

- Integrate with existing compliance workflows
- Scale across multiple organizations
- Support regulatory requirements like NIS2

## Troubleshooting

### Common Issues

#### Backend fails to start

- Verify `SNYK_TOKEN` and `SNYK_GROUP_ID` are correctly set in `.env`
- Check that the Snyk API token has appropriate permissions for the group
- Ensure port 8080 is available

#### Frontend connection errors

- Confirm backend is running on port 8080
- Check Docker network connectivity between services
- Verify proxy configuration in `package.json`

#### Export API timeouts

- Large datasets may require longer polling intervals
- Check Snyk service status if exports consistently fail
- Verify organization IDs are valid and accessible

#### Empty dashboard data

- Ensure the specified organizations contain projects with vulnerabilities
- Check filter parameters aren't too restrictive
- Verify CSV export contains expected data format

#### Logs and Debugging

- Backend logs: `docker-compose logs backend`
- Frontend logs: `docker-compose logs frontend`
- Full system logs: `docker-compose logs -f`

#### Performance Optimization

- Use specific organization IDs to reduce export size
- Apply date range filters to limit data scope
- Consider caching mechanisms for frequently accessed data
