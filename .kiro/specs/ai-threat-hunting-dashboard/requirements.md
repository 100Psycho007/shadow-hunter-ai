# Requirements Document

## Introduction

The AI Threat Hunting Dashboard is a local cybersecurity analytics and visualization tool designed to help security analysts and bug bounty hunters analyze reconnaissance scan results. The system will provide a Streamlit-based web interface that automatically loads JSON reports from a local directory, displays key metrics and visualizations, and optionally provides AI-assisted threat summaries when an API key is available.

## Requirements

### Requirement 1

**User Story:** As a bug bounty hunter, I want to automatically load all JSON reconnaissance reports from a local directory, so that I can quickly access and analyze all my scan results in one place.

#### Acceptance Criteria

1. WHEN the dashboard starts THEN the system SHALL automatically scan the /reports/ directory for all .json files
2. WHEN a JSON file is found THEN the system SHALL parse it according to the expected schema: {"target": "example.com", "scan_date": "2025-01-02", "subdomains": [...], "open_ports": {"80":"http"}, "vulnerabilities": [...], "ai_summary": null}
3. WHEN a JSON file cannot be parsed THEN the system SHALL log the error and continue processing other files
4. WHEN no JSON files are found THEN the system SHALL display a message indicating no reports are available

### Requirement 2

**User Story:** As a security analyst, I want to see key performance indicators and summary statistics, so that I can quickly understand the scope and scale of my reconnaissance data.

#### Acceptance Criteria

1. WHEN reports are loaded THEN the system SHALL display a KPI summary card showing total number of reports
2. WHEN reports are loaded THEN the system SHALL display a KPI summary card showing total number of unique subdomains across all reports
3. WHEN reports are loaded THEN the system SHALL display a KPI summary card showing average number of open ports per target
4. WHEN reports are loaded THEN the system SHALL display a KPI summary card showing total number of vulnerabilities found
5. WHEN no reports are available THEN the system SHALL display KPI cards with zero values

### Requirement 3

**User Story:** As a security researcher, I want to filter and search through my reconnaissance data, so that I can focus on specific targets, time periods, or findings of interest.

#### Acceptance Criteria

1. WHEN the dashboard loads THEN the system SHALL provide a sidebar with filtering options
2. WHEN multiple targets exist THEN the system SHALL provide a multi-select filter for targets
3. WHEN reports span multiple dates THEN the system SHALL provide a date range filter
4. WHEN I enter keywords THEN the system SHALL filter reports based on target names, subdomains, or vulnerability descriptions
5. WHEN I apply filters THEN the system SHALL update all visualizations and tables to reflect the filtered data
6. WHEN I clear filters THEN the system SHALL restore the full dataset view

### Requirement 4

**User Story:** As a cybersecurity analyst, I want to view detailed report information in an organized table format, so that I can examine specific findings and drill down into individual reports.

#### Acceptance Criteria

1. WHEN reports are displayed THEN the system SHALL show a table with columns for target, scan date, subdomain count, open ports count, and vulnerability count
2. WHEN I click on a table row THEN the system SHALL expand to show full report details including all subdomains, open ports, and vulnerabilities
3. WHEN I click on an expanded row THEN the system SHALL collapse the detailed view
4. WHEN the table contains many reports THEN the system SHALL provide pagination or scrolling functionality
5. WHEN no reports match the current filters THEN the system SHALL display a "No reports found" message

### Requirement 5

**User Story:** As a security analyst, I want to see visual charts and graphs of my reconnaissance data, so that I can quickly identify patterns and trends across my scans.

#### Acceptance Criteria

1. WHEN reports are loaded THEN the system SHALL display a bar chart showing the number of subdomains per target
2. WHEN reports contain open ports data THEN the system SHALL display a pie chart showing the distribution of open ports across all reports
3. WHEN reports span multiple dates THEN the system SHALL display a timeline chart showing report activity over time
4. WHEN filters are applied THEN the system SHALL update all charts to reflect the filtered data
5. WHEN no data is available for a chart THEN the system SHALL display an appropriate "No data" message

### Requirement 6

**User Story:** As a bug bounty hunter, I want AI-assisted summaries of my reconnaissance findings, so that I can quickly understand the security implications and prioritize my testing efforts.

#### Acceptance Criteria

1. WHEN an OPENROUTER_API_KEY environment variable is present THEN the system SHALL enable AI summary functionality
2. WHEN AI functionality is enabled AND I click an "AI Summary" button THEN the system SHALL send the report data to OpenRouter API for analysis
3. WHEN the AI API returns a response THEN the system SHALL display the threat assessment and risk summary
4. WHEN no API key is configured THEN the system SHALL display "AI functionality disabled - configure OPENROUTER_API_KEY to enable"
5. WHEN the AI API request fails THEN the system SHALL display an error message and continue functioning without AI features
6. WHEN AI summary is generated THEN the system SHALL cache the result to avoid repeated API calls for the same report

### Requirement 7

**User Story:** As a security professional, I want the dashboard to run entirely on my local machine, so that I can analyze sensitive reconnaissance data without exposing it to external services.

#### Acceptance Criteria

1. WHEN the application starts THEN the system SHALL run entirely on localhost without requiring external services
2. WHEN processing reports THEN the system SHALL only read from the local /reports/ directory
3. WHEN AI functionality is disabled THEN the system SHALL function completely offline
4. WHEN AI functionality is enabled THEN the system SHALL only connect to the configured OpenRouter API endpoint
5. WHEN the application is stopped THEN the system SHALL not leave any data on external services

### Requirement 8

**User Story:** As a developer or analyst, I want clear setup instructions and professional documentation, so that I can easily install, configure, and use the dashboard.

#### Acceptance Criteria

1. WHEN the project is distributed THEN the system SHALL include a comprehensive README.md file
2. WHEN setting up the project THEN the system SHALL provide clear installation instructions for Python dependencies
3. WHEN configuring the system THEN the system SHALL document how to set up the optional OpenRouter API key
4. WHEN running the application THEN the system SHALL provide clear instructions on how to start the Streamlit dashboard
5. WHEN contributing to the project THEN the system SHALL include a TODO section for future enhancements