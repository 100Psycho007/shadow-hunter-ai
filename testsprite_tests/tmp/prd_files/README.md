# AI Threat Hunting Dashboard

![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Streamlit](https://img.shields.io/badge/streamlit-1.28%2B-red.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A local cybersecurity analytics and visualization tool designed to help security analysts and bug bounty hunters analyze reconnaissance scan results. The dashboard provides an intuitive Streamlit-based web interface that automatically loads JSON reports from a local directory, displays key metrics and visualizations, and optionally provides AI-assisted threat summaries.

## Features

### 🔍 Automated Report Loading
- Automatically scans and loads all JSON reconnaissance reports from the `/reports/` directory
- Validates report schema and handles malformed files gracefully
- Supports standard reconnaissance output formats

### 📊 Comprehensive Analytics
- **KPI Dashboard**: View total reports, subdomains, open ports, and vulnerabilities at a glance
- **Interactive Visualizations**: 
  - Bar charts showing subdomain distribution per target
  - Pie charts displaying open port distributions
  - Timeline charts tracking reconnaissance activity over time
- **Advanced Filtering**: Filter by targets, date ranges, and keywords

### 🤖 AI-Powered Threat Analysis
- Optional integration with OpenRouter API for intelligent threat summaries
- Automated risk assessment and security implications analysis
- Caching system to avoid duplicate API calls
- Graceful degradation when AI features are disabled

### 🛡️ Security & Privacy
- **100% Local Processing**: All sensitive data remains on your machine
- **Offline Capable**: Full functionality without internet connection (when AI is disabled)
- **No Data Persistence**: No external data storage or tracking

### 📋 Detailed Report Management
- Expandable table view with complete report details
- Sortable columns and pagination for large datasets
- Drill-down capabilities for individual findings

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup Instructions

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd ai-threat-hunting-dashboard
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Create reports directory** (if it doesn't exist)
   ```bash
   mkdir reports
   ```

4. **Optional: Configure AI Integration**
   
   To enable AI-powered threat summaries, set your OpenRouter API key:
   
   **Windows (Command Prompt):**
   ```cmd
   set OPENROUTER_API_KEY=your_api_key_here
   ```
   
   **Windows (PowerShell):**
   ```powershell
   $env:OPENROUTER_API_KEY="your_api_key_here"
   ```
   
   **Linux/macOS:**
   ```bash
   export OPENROUTER_API_KEY=your_api_key_here
   ```
   
   You can obtain an API key from [OpenRouter](https://openrouter.ai/).

## Usage

### Starting the Dashboard

1. **Launch the Streamlit application**
   ```bash
   streamlit run dashboard.py
   ```

2. **Access the dashboard**
   - Open your web browser and navigate to `http://localhost:8501`
   - The dashboard will automatically load any JSON reports from the `/reports/` directory

### Report Format

Place your reconnaissance reports in the `/reports/` directory as JSON files. The expected schema is:

```json
{
  "target": "example.com",
  "scan_date": "2025-01-02",
  "subdomains": [
    "www.example.com",
    "api.example.com",
    "admin.example.com"
  ],
  "open_ports": {
    "80": "http",
    "443": "https",
    "22": "ssh"
  },
  "vulnerabilities": [
    {
      "severity": "medium",
      "title": "Outdated Server Version",
      "description": "Server running outdated Apache version",
      "affected_service": "http",
      "cve_id": "CVE-2023-12345"
    }
  ],
  "ai_summary": null
}
```

### Using the Dashboard

1. **View KPI Summary**: Check the top cards for quick statistics
2. **Apply Filters**: Use the sidebar to filter by targets, dates, or keywords
3. **Explore Visualizations**: Analyze patterns in the interactive charts
4. **Review Detailed Reports**: Click on table rows to expand full details
5. **Generate AI Summaries**: Click "AI Summary" buttons for threat analysis (requires API key)

### Screenshots

*[Screenshot placeholders - Add actual screenshots here]*

- Dashboard Overview
- KPI Cards and Filters
- Interactive Charts
- Detailed Report View
- AI Summary Example

## Project Structure

```
ai-threat-hunting-dashboard/
├── src/
│   ├── __init__.py          # Package initialization
│   ├── loader.py            # Report loading and validation
│   ├── analytics.py         # Data processing and KPI calculations
│   └── ai.py               # AI integration and OpenRouter API
├── reports/                 # JSON report files directory
│   ├── sample.json         # Example report format
│   └── testcorp.json       # Additional sample data
├── assets/                  # Static assets (logos, images)
│   └── .gitkeep
├── dashboard.py            # Main Streamlit application
├── requirements.txt        # Python dependencies
├── .gitignore             # Git ignore rules
└── README.md              # This file
```

## Dependencies

The application requires the following Python packages:

- **streamlit** (>=1.28.0): Web application framework
- **plotly** (>=5.15.0): Interactive visualization library
- **pandas** (>=2.0.0): Data manipulation and analysis
- **requests** (>=2.31.0): HTTP library for API calls

See `requirements.txt` for complete dependency list with version specifications.

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENROUTER_API_KEY` | Optional | API key for AI-powered threat summaries |

### Directory Structure

- **`/reports/`**: Place your JSON reconnaissance reports here
- **`/assets/`**: Static assets like logos and images
- **`/src/`**: Core application modules

## Troubleshooting

### Common Issues

**Dashboard won't start**
- Ensure Python 3.8+ is installed: `python --version`
- Install dependencies: `pip install -r requirements.txt`
- Check for port conflicts on 8501

**No reports showing**
- Verify JSON files are in the `/reports/` directory
- Check JSON file format matches expected schema
- Look for error messages in the Streamlit console

**AI summaries not working**
- Verify `OPENROUTER_API_KEY` environment variable is set
- Check API key validity at OpenRouter dashboard
- Ensure internet connection for API calls

**Performance issues with large datasets**
- Consider filtering reports by date range
- Check available system memory
- Use pagination for very large report sets

### Getting Help

If you encounter issues:

1. Check the Streamlit console for error messages
2. Verify your JSON report format matches the expected schema
3. Ensure all dependencies are properly installed
4. Check that the `/reports/` directory exists and contains valid files

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Submit a pull request with a clear description

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with [Streamlit](https://streamlit.io/) for the web interface
- Visualizations powered by [Plotly](https://plotly.com/)
- AI integration via [OpenRouter](https://openrouter.ai/)
## T
ODO - Future Enhancements

### 🚀 Planned Features

#### Multi-User Mode
- **User Authentication**: Implement login system with role-based access control
- **User Workspaces**: Separate report collections and settings per user
- **Collaboration Features**: Share reports and findings between team members
- **Audit Logging**: Track user actions and report access for compliance

#### Enhanced Export Capabilities
- **PDF Report Generation**: Export filtered reports and visualizations to PDF
- **Excel Export**: Export tabular data with formatting and charts
- **Custom Report Templates**: Create branded report templates for clients
- **Automated Report Scheduling**: Generate and email reports on schedule

#### Advanced Analytics
- **Trend Analysis**: Historical comparison and trend identification
- **Risk Scoring**: Automated vulnerability risk assessment and prioritization
- **Correlation Engine**: Identify patterns across multiple reconnaissance scans
- **Baseline Comparison**: Compare current scans against historical baselines

#### Data Integration
- **Database Support**: PostgreSQL, MySQL, and SQLite backend options
- **API Endpoints**: RESTful API for programmatic access to reports and analytics
- **Webhook Integration**: Real-time notifications for new reports and findings
- **SIEM Integration**: Export findings to popular SIEM platforms

### 🔧 Tool Integrations

#### Reconnaissance Tool Connectors
- **Nmap Integration**: Direct import from Nmap XML output
- **Masscan Support**: Parse and import Masscan results
- **Subfinder Integration**: Automatic subdomain enumeration import
- **Nuclei Integration**: Import vulnerability scan results from Nuclei
- **Amass Support**: Import asset discovery results from Amass
- **Custom Parser Framework**: Plugin system for additional tool formats

#### Security Platform Integration
- **Shodan API**: Enrich findings with Shodan intelligence data
- **VirusTotal Integration**: Automatic malware and reputation checking
- **CVE Database**: Real-time CVE lookup and severity scoring
- **Threat Intelligence Feeds**: Integration with commercial threat feeds

### ⚡ Performance & Scalability

#### Performance Optimizations
- **Database Indexing**: Optimize queries for large datasets (10,000+ reports)
- **Lazy Loading**: Implement progressive data loading for better UX
- **Caching Layer**: Redis-based caching for frequently accessed data
- **Background Processing**: Async processing for large file imports
- **Memory Optimization**: Efficient data structures for large-scale analysis

#### Scalability Improvements
- **Horizontal Scaling**: Support for distributed processing across multiple nodes
- **Load Balancing**: Handle multiple concurrent users efficiently
- **Data Partitioning**: Partition large datasets by date or organization
- **Microservices Architecture**: Break down monolithic structure for better scaling
- **Container Support**: Docker and Kubernetes deployment configurations

### 🎨 User Experience Enhancements

#### Advanced UI Features
- **Dark Mode**: Toggle between light and dark themes
- **Customizable Dashboards**: Drag-and-drop dashboard customization
- **Advanced Filtering**: Complex filter combinations with saved filter sets
- **Real-time Updates**: Live dashboard updates as new reports are added
- **Mobile Responsive**: Optimized mobile and tablet viewing experience

#### Visualization Improvements
- **3D Network Graphs**: Interactive network topology visualization
- **Geolocation Mapping**: Map-based visualization of target locations
- **Attack Path Visualization**: Visual representation of potential attack vectors
- **Custom Chart Builder**: User-defined chart creation and sharing
- **Interactive Timeline**: Detailed timeline with event correlation

### 🔒 Security & Compliance

#### Enhanced Security Features
- **Encryption at Rest**: Encrypt stored reports and sensitive data
- **Secure API Authentication**: JWT-based API authentication with rate limiting
- **Data Anonymization**: Tools for sanitizing sensitive data in reports
- **Backup & Recovery**: Automated backup and disaster recovery procedures
- **Security Audit Logging**: Comprehensive audit trail for all system actions

#### Compliance Features
- **GDPR Compliance**: Data privacy controls and user consent management
- **SOC 2 Compliance**: Security controls and monitoring for service organizations
- **Data Retention Policies**: Configurable data retention and automatic cleanup
- **Access Control Matrix**: Fine-grained permissions and role management
- **Compliance Reporting**: Generate compliance reports for various frameworks

### 🤖 AI & Machine Learning

#### Advanced AI Features
- **Custom AI Models**: Train models on organization-specific threat patterns
- **Anomaly Detection**: ML-based detection of unusual reconnaissance patterns
- **Predictive Analytics**: Predict likely attack vectors based on reconnaissance data
- **Natural Language Queries**: Ask questions about data in natural language
- **Automated Threat Hunting**: AI-driven identification of potential threats

#### Intelligence Enhancement
- **Threat Actor Attribution**: Link reconnaissance patterns to known threat actors
- **Campaign Tracking**: Identify and track multi-stage attack campaigns
- **False Positive Reduction**: ML-based filtering of noise and false positives
- **Risk Prioritization**: AI-driven vulnerability and target prioritization
- **Contextual Recommendations**: Intelligent suggestions for next steps

### 📱 Platform Extensions

#### Mobile Applications
- **iOS App**: Native iOS application for on-the-go report viewing
- **Android App**: Native Android application with offline capabilities
- **Progressive Web App**: Enhanced mobile web experience with offline support
- **Push Notifications**: Real-time alerts for critical findings

#### Desktop Applications
- **Electron Desktop App**: Cross-platform desktop application
- **System Tray Integration**: Background monitoring and notifications
- **Offline Mode**: Full functionality without internet connectivity
- **Local File Watchers**: Automatic import of new reports from file system

### 🔌 Integration Ecosystem

#### Third-Party Integrations
- **Slack/Teams Integration**: Send alerts and reports to team channels
- **Jira Integration**: Automatically create tickets for critical findings
- **Email Notifications**: Customizable email alerts and report delivery
- **Calendar Integration**: Schedule and track reconnaissance activities
- **Single Sign-On (SSO)**: Integration with corporate identity providers

#### Developer Tools
- **CLI Tool**: Command-line interface for automation and scripting
- **Python SDK**: Comprehensive SDK for custom integrations
- **Webhook Framework**: Extensible webhook system for custom notifications
- **Plugin Architecture**: Framework for community-developed extensions
- **API Documentation**: Comprehensive API documentation with examples

---

### 📋 Implementation Priority

**Phase 1 (High Priority)**
- PDF Export functionality
- Database backend support
- Basic multi-user authentication
- Nmap/Masscan integration

**Phase 2 (Medium Priority)**
- Advanced analytics and trend analysis
- Mobile responsive design
- API endpoints and webhook integration
- Performance optimizations

**Phase 3 (Future)**
- AI/ML enhancements
- Mobile applications
- Advanced security features
- Enterprise compliance features

### 🤝 Contributing to Future Development

We welcome contributions to any of these planned features! If you're interested in implementing any of these enhancements:

1. **Check existing issues** for related discussions
2. **Create a feature request** to discuss implementation approach
3. **Fork the repository** and create a feature branch
4. **Submit a pull request** with comprehensive testing

For major features, please create an issue first to discuss the implementation approach and ensure alignment with project goals.