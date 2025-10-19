```
   ███████╗██╗  ██╗ █████╗ ██████╗ ██████╗  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
   ███████╗███████║███████║██████╔╝██████╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
   ╚════██║██╔══██║██╔══██║██╔══██╗██╔══██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
   ███████║██║  ██║██║  ██║██║  ██║██║  ██║ ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" />
  <img src="https://img.shields.io/badge/streamlit-1.28%2B-red.svg" />
  <img src="https://img.shields.io/badge/security-threat--hunting-orange.svg" />
  <img src="https://img.shields.io/badge/license-MIT-green.svg" />
</p>

# 🛡️ AI Threat Hunting Dashboard

A clean, intuitive cybersecurity analytics tool for analyzing reconnaissance scan results. Features a modern Streamlit interface with AI-powered threat analysis capabilities.

## ✨ Features

### 🎯 **Dual Analysis Modes**
- **📋 Single Report Analysis**: Deep dive into individual targets with organized tabs
- **📊 Multi-Report Comparison**: Compare multiple targets side-by-side

### 🔍 **Automated Report Loading**
- Automatically loads JSON reconnaissance reports from `/reports/` directory
- Validates report schema and handles malformed files gracefully
- Supports standard reconnaissance output formats

### 📊 **Comprehensive Analytics**
- **Beautiful KPI Cards**: Total reports, subdomains, open ports, vulnerabilities
- **Interactive Visualizations**: 
  - Subdomain distribution charts
  - Port analysis with risk assessment
  - Timeline activity tracking
- **Risk Assessment**: Automatic risk level calculation per report

### 🤖 **AI-Powered Analysis**
- Integration with OpenRouter API for threat assessment
- Individual and batch AI summary generation
- Intelligent caching to minimize API usage
- Clear risk categorization and recommendations

### 🎨 **Clean User Interface**
- Modern, intuitive design with gradient KPI cards
- Organized tabs for easy navigation
- Color-coded severity levels (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)
- Responsive layout that works on all screen sizes

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/100Psycho007/shadow-hunter-ai.git
   cd shadow-hunter-ai
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Add your reconnaissance reports**
   - Place JSON report files in the `reports/` directory
   - See [Report Format](#report-format) for the expected schema

4. **Run the dashboard**
   ```bash
   streamlit run dashboard.py
   ```

5. **Open your browser**
   - Navigate to `http://localhost:8501`
   - Start analyzing your reconnaissance data!

## 📋 Report Format

Place JSON files in the `reports/` directory with this structure:

```json
{
  "target": "example.com",
  "scan_date": "2025-01-15",
  "subdomains": [
    "www.example.com",
    "api.example.com",
    "admin.example.com"
  ],
  "open_ports": {
    "22": "ssh",
    "80": "http", 
    "443": "https",
    "3306": "mysql"
  },
  "vulnerabilities": [
    {
      "severity": "high",
      "title": "Outdated SSH Server",
      "description": "SSH server running outdated version",
      "affected_service": "ssh",
      "cve_id": "CVE-2023-1234"
    }
  ]
}
```

## 🤖 AI Configuration

To enable AI-powered threat analysis:

1. **Get an API key** from [OpenRouter.ai](https://openrouter.ai)
2. **Enter the key** in the sidebar AI Configuration section
3. **Generate summaries** for individual reports or in batch
4. **View intelligent analysis** with risk assessment and recommendations

## 🎯 How to Use

### Single Report Analysis
1. Select **"📋 Single Report"** mode in the sidebar
2. Choose a report from the dropdown
3. Navigate through organized tabs:
   - **🌐 Subdomains**: View all discovered subdomains
   - **🔌 Open Ports**: See ports with risk assessment
   - **🚨 Vulnerabilities**: Severity-grouped security issues
   - **🤖 AI Analysis**: Generate intelligent threat summaries

### Multi-Report Comparison
1. Select **"📊 Compare Multiple"** mode in the sidebar
2. Choose multiple targets to compare
3. View side-by-side comparison tables
4. Analyze aggregated vulnerability summaries
5. Compare risk levels across targets

## 🛠️ Technical Details

### Architecture
- **Frontend**: Streamlit web framework
- **Visualization**: Plotly for interactive charts
- **Data Processing**: Pandas for analytics
- **AI Integration**: OpenRouter API for threat analysis
- **Caching**: Built-in caching for performance

### Security Features
- **Local Processing**: All data stays on your machine
- **No External Storage**: Reports never leave your environment
- **API Key Security**: Secure handling of AI service credentials
- **Input Validation**: Comprehensive report schema validation

## 📁 Project Structure

```
ai-threat-hunting-dashboard/
├── dashboard.py              # Main application
├── src/
│   ├── loader.py            # Report loading and validation
│   ├── analytics.py         # Data analysis and KPI calculation
│   └── ai.py               # AI integration and caching
├── reports/                 # Place your JSON reports here
│   ├── sample.json         # Example report format
│   └── testcorp.json       # Another example
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🔧 Troubleshooting

### Common Issues

**No reports showing?**
- Ensure JSON files are in the `reports/` directory
- Check that files follow the expected schema
- Click "🔄 Refresh Data" in the sidebar

**Charts not displaying?**
- The dashboard includes fallback displays if Plotly fails
- Check browser console for JavaScript errors
- Try refreshing the page

**AI analysis not working?**
- Verify your OpenRouter API key is correct
- Check your account has sufficient credits
- Ensure internet connection is stable

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

If you encounter any issues or have questions, please open an issue on the repository.

---

**Built with ❤️ for the cybersecurity community**