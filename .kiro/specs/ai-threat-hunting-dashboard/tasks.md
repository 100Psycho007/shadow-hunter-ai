# Implementation Plan

- [x] 1. Set up project structure and core interfaces





  - Create directory structure for src/, reports/, and assets/ folders
  - Create requirements.txt with all necessary dependencies
  - Create .gitignore file for Python projects
  - Set up basic project configuration files
  - _Requirements: 7.1, 8.1, 8.4_

- [x] 2. Implement data loading and validation module




  - [x] 2.1 Create ReportLoader class with JSON parsing functionality


    - Write ReportLoader class in src/loader.py
    - Implement load_reports() method to scan directory and parse JSON files
    - Add validate_report_schema() method to check JSON structure
    - Handle file I/O errors and malformed JSON gracefully
    - _Requirements: 1.1, 1.2, 1.3, 1.4_

  - [x] 2.2 Create sample JSON report for testing


    - Write sample.json in reports/ directory following the defined schema
    - Include realistic reconnaissance data with subdomains, ports, and vulnerabilities
    - _Requirements: 1.2, 8.1_

  - [x] 2.3 Write unit tests for data loading functionality
    - Create test cases for valid JSON parsing
    - Test error handling for malformed files
    - Test schema validation edge cases
    - _Requirements: 1.2, 1.3_

- [x] 3. Implement analytics and data processing module




  - [x] 3.1 Create ReportAnalytics class for KPI calculations

    - Write ReportAnalytics class in src/analytics.py
    - Implement calculate_kpis() method for summary statistics
    - Add methods for subdomain counts, port distribution, and timeline data
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [x] 3.2 Implement filtering and search functionality

    - Add filter_reports() method to handle target, date, and keyword filters
    - Implement search logic for targets, subdomains, and vulnerability descriptions
    - Handle edge cases for empty filter results
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

  - [x] 3.3 Write unit tests for analytics functionality
    - Test KPI calculation accuracy
    - Test filtering logic with various combinations
    - Test edge cases with empty datasets
    - _Requirements: 2.5, 3.6_

- [x] 4. Implement AI integration module




  - [x] 4.1 Create AIAnalyzer class for OpenRouter integration


    - Write AIAnalyzer class in src/ai.py
    - Implement API key detection and validation
    - Add generate_summary() method for threat analysis
    - Handle API errors and timeouts gracefully
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_


  - [x] 4.2 Implement AI summary caching mechanism

    - Add caching logic to avoid duplicate API calls for same reports
    - Store AI summaries in report data structure
    - Handle cache invalidation when reports are updated
    - _Requirements: 6.6_

  - [x] 4.3 Write unit tests for AI integration
    - Test API key detection logic
    - Mock API responses for testing
    - Test error handling scenarios
    - _Requirements: 6.4, 6.5_

- [x] 5. Create main Streamlit dashboard interface





  - [x] 5.1 Implement basic dashboard layout and navigation


    - Create dashboard.py with Streamlit app structure
    - Set up sidebar for filters and controls
    - Create main content area with placeholder sections
    - Add application header and branding
    - _Requirements: 7.1, 8.4_

  - [x] 5.2 Implement KPI summary cards display


    - Create KPI cards showing total reports, subdomains, ports, and vulnerabilities
    - Use Streamlit columns for responsive layout
    - Handle zero-state when no reports are available
    - Update cards dynamically based on applied filters
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [x] 5.3 Implement filtering sidebar interface


    - Add multi-select widget for target filtering
    - Create date range picker for temporal filtering
    - Add text input for keyword search
    - Implement toggle for AI summary visibility
    - Connect filters to data processing logic
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

- [x] 6. Implement data visualization charts




  - [x] 6.1 Create subdomain distribution bar chart


    - Use Plotly to create interactive bar chart showing subdomains per target
    - Handle cases with many targets through scrolling or pagination
    - Update chart dynamically based on applied filters
    - _Requirements: 5.1, 5.4_

  - [x] 6.2 Create open ports distribution pie chart


    - Implement pie chart showing distribution of open ports across all reports
    - Group less common ports into "Other" category for readability
    - Handle empty data states appropriately
    - _Requirements: 5.2, 5.4_

  - [x] 6.3 Create timeline chart for report activity


    - Build timeline visualization showing report creation dates
    - Aggregate reports by date for cleaner visualization
    - Handle date parsing and formatting consistently
    - _Requirements: 5.3, 5.4_

- [x] 7. Implement detailed report table view




  - [x] 7.1 Create main reports table with summary information


    - Display table with columns for target, date, subdomain count, ports, vulnerabilities
    - Implement sorting functionality for each column
    - Add pagination or scrolling for large datasets
    - _Requirements: 4.1, 4.4_

  - [x] 7.2 Implement expandable row details


    - Add click functionality to expand rows showing full report details
    - Display complete lists of subdomains, open ports, and vulnerabilities
    - Format vulnerability information with severity indicators
    - Implement collapse functionality for expanded rows
    - _Requirements: 4.2, 4.3_

  - [x] 7.3 Handle empty states and error messages


    - Show appropriate message when no reports match filters
    - Display helpful guidance when reports directory is empty
    - Handle table rendering errors gracefully
    - _Requirements: 4.5, 1.4_

- [x] 8. Integrate AI summary functionality into UI




  - [x] 8.1 Add AI summary buttons and controls


    - Create AI summary buttons for individual reports
    - Show loading indicators during API calls
    - Display AI-disabled message when no API key is configured
    - _Requirements: 6.1, 6.4_

  - [x] 8.2 Implement AI summary display and error handling


    - Show AI-generated threat assessments in expandable sections
    - Handle API errors with user-friendly error messages
    - Display cached summaries when available
    - Provide retry functionality for failed API calls
    - _Requirements: 6.2, 6.3, 6.5, 6.6_

- [x] 9. Create comprehensive documentation and setup




  - [x] 9.1 Write detailed README.md file


    - Create project description and feature overview
    - Add installation instructions for Python dependencies
    - Document environment variable configuration for API key
    - Include usage instructions and screenshots placeholders
    - Add badges for Python version, Streamlit, and license
    - _Requirements: 8.1, 8.2, 8.3, 8.4_

  - [x] 9.2 Create TODO section for future enhancements


    - Document planned features like multi-user mode and PDF export
    - List potential integrations with reconnaissance tools
    - Outline scalability improvements and performance optimizations
    - _Requirements: 8.5_

- [ ] 10. Final integration and testing




  - [x] 10.1 Integrate all modules into working dashboard


    - Connect data loader to analytics module
    - Wire analytics to UI components
    - Integrate AI functionality with user interface
    - Test complete user workflows from file loading to visualization
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [x] 10.2 Perform end-to-end testing and bug fixes


    - Test with various JSON file formats and edge cases
    - Verify filtering and search functionality across all components
    - Test AI integration with and without API key
    - Fix any integration issues and polish user experience
    - _Requirements: 1.3, 3.5, 6.4, 6.5_