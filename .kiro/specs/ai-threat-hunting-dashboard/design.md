# Design Document

## Overview

The AI Threat Hunting Dashboard is a Streamlit-based web application that provides cybersecurity analysts with a comprehensive interface for analyzing reconnaissance scan results. The system follows a modular architecture with separate components for data loading, analytics processing, AI integration, and user interface presentation.

## Architecture

The application follows a layered architecture pattern:

```
┌─────────────────────────────────────────┐
│           Streamlit UI Layer            │
│  (dashboard.py - Main Interface)        │
├─────────────────────────────────────────┤
│          Business Logic Layer           │
│  ┌─────────────┬─────────────────────┐  │
│  │ Analytics   │    AI Integration   │  │
│  │ (analytics.py) │    (ai.py)       │  │
│  └─────────────┴─────────────────────┘  │
├─────────────────────────────────────────┤
│           Data Access Layer             │
│        (loader.py - File I/O)           │
├─────────────────────────────────────────┤
│            Data Storage                 │
│     (Local JSON files in /reports/)     │
└─────────────────────────────────────────┘
```

### Key Architectural Principles

1. **Separation of Concerns**: Each module has a single responsibility
2. **Loose Coupling**: Modules interact through well-defined interfaces
3. **Local-First**: All data processing happens locally except optional AI calls
4. **Graceful Degradation**: System functions without AI when API key is unavailable

## Components and Interfaces

### 1. Data Loader Module (`src/loader.py`)

**Purpose**: Handle file system operations and JSON parsing

**Key Classes/Functions**:
```python
class ReportLoader:
    def load_reports(self, directory_path: str) -> List[Dict]
    def validate_report_schema(self, report: Dict) -> bool
    def get_report_files(self, directory_path: str) -> List[str]

def parse_json_report(file_path: str) -> Optional[Dict]
```

**Responsibilities**:
- Scan `/reports/` directory for JSON files
- Parse and validate JSON structure against expected schema
- Handle file I/O errors gracefully
- Return structured data for processing

### 2. Analytics Module (`src/analytics.py`)

**Purpose**: Process report data and generate statistics

**Key Classes/Functions**:
```python
class ReportAnalytics:
    def calculate_kpis(self, reports: List[Dict]) -> Dict
    def filter_reports(self, reports: List[Dict], filters: Dict) -> List[Dict]
    def generate_chart_data(self, reports: List[Dict]) -> Dict

def get_subdomain_counts(reports: List[Dict]) -> Dict[str, int]
def get_port_distribution(reports: List[Dict]) -> Dict[str, int]
def get_timeline_data(reports: List[Dict]) -> List[Tuple[str, int]]
```

**Responsibilities**:
- Calculate KPI metrics (totals, averages, counts)
- Apply user-defined filters to dataset
- Prepare data structures for visualization
- Handle date parsing and aggregation

### 3. AI Integration Module (`src/ai.py`)

**Purpose**: Interface with OpenRouter API for threat analysis

**Key Classes/Functions**:
```python
class AIAnalyzer:
    def __init__(self, api_key: Optional[str])
    def is_enabled(self) -> bool
    def generate_summary(self, report: Dict) -> Optional[str]
    def format_prompt(self, report: Dict) -> str

def check_api_key() -> Optional[str]
```

**Responsibilities**:
- Check for API key availability
- Format report data for AI analysis
- Make API calls to OpenRouter
- Handle API errors and timeouts
- Cache results to avoid duplicate calls

### 4. Main Dashboard (`dashboard.py`)

**Purpose**: Streamlit UI orchestration and user interaction

**Key Components**:
- Sidebar filters and controls
- KPI summary cards
- Data table with expandable rows
- Chart visualizations
- AI summary interface

## Data Models

### Report Schema
```python
{
    "target": str,           # Domain/IP being scanned
    "scan_date": str,        # ISO format date string
    "subdomains": List[str], # List of discovered subdomains
    "open_ports": Dict[str, str], # Port number -> service mapping
    "vulnerabilities": List[Dict], # Vulnerability objects
    "ai_summary": Optional[str]    # Cached AI analysis
}
```

### Vulnerability Schema
```python
{
    "severity": str,         # "low", "medium", "high", "critical"
    "title": str,           # Vulnerability name/title
    "description": str,     # Detailed description
    "affected_service": str, # Service/port affected
    "cve_id": Optional[str] # CVE identifier if available
}
```

### Filter State
```python
{
    "selected_targets": List[str],
    "date_range": Tuple[datetime, datetime],
    "keyword_search": str,
    "show_ai_summaries": bool
}
```

## User Interface Design

### Layout Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    Header & Title                           │
├─────────────┬───────────────────────────────────────────────┤
│   Sidebar   │                Main Content                   │
│             │                                               │
│ • Filters   │  ┌─────────────────────────────────────────┐  │
│ • Controls  │  │           KPI Cards                     │  │
│ • AI Toggle │  │  [Reports] [Subdomains] [Ports] [Vulns] │  │
│             │  └─────────────────────────────────────────┘  │
│             │                                               │
│             │  ┌─────────────────────────────────────────┐  │
│             │  │              Charts                     │  │
│             │  │  [Bar Chart] [Pie Chart] [Timeline]     │  │
│             │  └─────────────────────────────────────────┘  │
│             │                                               │
│             │  ┌─────────────────────────────────────────┐  │
│             │  │           Data Table                    │  │
│             │  │  Expandable rows with details           │  │
│             │  └─────────────────────────────────────────┘  │
└─────────────┴───────────────────────────────────────────────┘
```

### Streamlit Components

1. **st.sidebar**: Filters and controls
2. **st.columns**: KPI cards layout
3. **st.plotly_chart**: Interactive visualizations
4. **st.dataframe**: Report table with selection
5. **st.expander**: Detailed report views
6. **st.button**: AI summary triggers

## Error Handling

### File System Errors
- **Missing /reports/ directory**: Create directory and show setup instructions
- **Corrupted JSON files**: Log error, skip file, continue processing
- **Permission errors**: Display clear error message with resolution steps

### API Errors
- **Missing API key**: Graceful degradation with disabled AI features
- **Network timeouts**: Retry logic with exponential backoff
- **API rate limits**: Queue requests and show progress indicators
- **Invalid responses**: Log error and show user-friendly message

### Data Validation Errors
- **Schema mismatches**: Log warnings and attempt partial parsing
- **Date parsing failures**: Use filename or current date as fallback
- **Empty datasets**: Show appropriate empty state messages

## Testing Strategy

### Unit Testing
- **Data Loader**: Test JSON parsing, schema validation, error handling
- **Analytics**: Test KPI calculations, filtering logic, chart data generation
- **AI Integration**: Test API formatting, response parsing, error scenarios

### Integration Testing
- **End-to-End Workflows**: Test complete user journeys from file load to visualization
- **Filter Interactions**: Test complex filter combinations and edge cases
- **AI Integration**: Test with mock API responses and error conditions

### Manual Testing
- **UI Responsiveness**: Test with various screen sizes and data volumes
- **Performance**: Test with large datasets and multiple reports
- **User Experience**: Validate intuitive navigation and clear error messages

## Performance Considerations

### Data Loading
- **Lazy Loading**: Load reports on-demand rather than at startup
- **Caching**: Cache parsed reports in memory to avoid re-parsing
- **Pagination**: Implement pagination for large datasets

### Visualization
- **Chart Optimization**: Use Plotly's built-in performance optimizations
- **Data Sampling**: Sample large datasets for chart rendering
- **Progressive Loading**: Show loading indicators for long operations

### AI Integration
- **Request Batching**: Batch multiple reports for AI analysis
- **Response Caching**: Store AI summaries to avoid duplicate API calls
- **Async Processing**: Use async calls to prevent UI blocking

## Security Considerations

### Data Privacy
- **Local Processing**: All sensitive data remains on local machine
- **API Data**: Only send necessary data to AI service, not full reports
- **No Persistence**: Don't store API keys in configuration files

### Input Validation
- **File Path Sanitization**: Prevent directory traversal attacks
- **JSON Validation**: Validate all input data against expected schemas
- **API Response Validation**: Validate AI API responses before display

## Deployment and Configuration

### Environment Setup
```bash
# Required Python packages
streamlit>=1.28.0
plotly>=5.15.0
pandas>=2.0.0
requests>=2.31.0

# Optional environment variables
OPENROUTER_API_KEY=your_api_key_here
```

### Directory Structure
```
ai-threat-hunting-dashboard/
├── src/
│   ├── loader.py
│   ├── analytics.py
│   └── ai.py
├── dashboard.py
├── reports/
│   └── sample.json
├── assets/
│   └── logo.png
├── requirements.txt
├── .gitignore
└── README.md
```

### Startup Process
1. Check Python version compatibility
2. Validate required dependencies
3. Create /reports/ directory if missing
4. Load environment variables
5. Initialize Streamlit application
6. Display setup instructions if no reports found