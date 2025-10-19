#!/usr/bin/env python3
"""
AI Threat Hunting Dashboard
A Streamlit-based cybersecurity analytics and visualization tool
"""

import streamlit as st
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    pd = None

import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
from typing import List, Dict, Optional
import os
import sys
import logging
import warnings

# Suppress ALL PyArrow warnings and errors completely
# Suppress all warnings that might be related to PyArrow
warnings.filterwarnings('ignore', category=UserWarning)
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)
warnings.filterwarnings('ignore', message='.*pyarrow.*', module='.*')
warnings.filterwarnings('ignore', message='.*PyArrow.*', module='.*')
warnings.filterwarnings('ignore', message='.*arrow.*', module='.*')

# Set environment variables to prevent PyArrow issues
os.environ['PYARROW_IGNORE_TIMEZONE'] = '1'
os.environ['PANDAS_BACKEND'] = 'numpy'

# Multiple approaches to ensure pandas doesn't use PyArrow
if PANDAS_AVAILABLE:
    try:
        # For newer pandas versions
        pd.options.mode.dtype_backend = "numpy_nullable"
    except (AttributeError, ValueError):
        pass

    try:
        # Alternative approach for different pandas versions
        pd.set_option('mode.dtype_backend', 'numpy_nullable')
    except (AttributeError, ValueError):
        pass

# Configure logging to suppress PyArrow messages
logging.getLogger('streamlit').setLevel(logging.ERROR)
logging.getLogger('pandas').setLevel(logging.ERROR)
logging.getLogger('pyarrow').setLevel(logging.ERROR)

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from loader import ReportLoader
from analytics import ReportAnalytics
from ai import AIAnalyzer
import json
import stat
import hashlib

# API Key Storage Functions
CONFIG_FILE = ".dashboard_config.json"

def load_api_key():
    """Load saved API key from config file"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                return config.get('openrouter_api_key', '')
    except Exception:
        pass
    return ''

def save_api_key(api_key):
    """Save API key to config file with secure permissions"""
    try:
        config = {}
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        
        config['openrouter_api_key'] = api_key
        
        # Write the config file
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Set restrictive permissions (owner read/write only)
        try:
            os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except (OSError, AttributeError):
            # chmod may fail on some platforms (e.g., Windows)
            pass
        
        # Display security warning
        st.warning("⚠️ **Security Notice**: API key is stored in plain text in the config file. "
                  "Ensure this file is not accessible to unauthorized users and consider using "
                  "environment variables for production deployments.")
        
    except Exception as e:
        st.error(f"Failed to save API key: {str(e)}")

def clear_api_key():
    """Clear saved API key"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            
            config.pop('openrouter_api_key', None)
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Maintain restrictive permissions
            try:
                os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0600
            except (OSError, AttributeError):
                # chmod may fail on some platforms (e.g., Windows)
                pass
    except Exception:
        pass

# AI Cache Functions
AI_CACHE_FILE = "ai_cache.json"

def get_report_cache_key(report):
    """Generate a unique cache key for a report"""
    # Use same logic as ReportAICache.get_cache_key for consistency
    cache_data = {
        "target": report.get("target", ""),
        "scan_date": report.get("scan_date", ""),
        "subdomains": sorted(report.get("subdomains", [])),
        "open_ports": dict(sorted(report.get("open_ports", {}).items())),
        "vulnerabilities": sorted([
            {
                "severity": v.get("severity", ""),
                "title": v.get("title", ""),
                "description": v.get("description", "")
            }
            for v in report.get("vulnerabilities", [])
        ], key=lambda x: (x["severity"], x["title"]))
    }
    cache_string = json.dumps(cache_data, sort_keys=True)
    return hashlib.md5(cache_string.encode()).hexdigest()

def load_ai_cache():
    """Load AI analysis cache from file"""
    try:
        if os.path.exists(AI_CACHE_FILE):
            with open(AI_CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        st.error(f"Failed to load AI cache: {str(e)}")
    return {}

def save_ai_cache(cache):
    """Save AI analysis cache to file"""
    try:
        with open(AI_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except Exception as e:
        st.error(f"Failed to save AI cache: {str(e)}")

def get_cached_ai_summary(report):
    """Get cached AI summary for a report"""
    cache = load_ai_cache()
    cache_key = get_report_cache_key(report)
    cache_entry = cache.get(cache_key)
    if cache_entry and isinstance(cache_entry, dict):
        return cache_entry.get('summary')
    return None

def cache_ai_summary(report, summary):
    """Cache AI summary for a report"""
    cache = load_ai_cache()
    cache_key = get_report_cache_key(report)
    cache[cache_key] = {
        'summary': summary,
        'target': report.get('target', 'unknown'),
        'timestamp': datetime.now().isoformat(),
        'cache_key': cache_key
    }
    save_ai_cache(cache)

# Page configuration
st.set_page_config(
    page_title="AI Threat Hunting Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for clean styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
    }
    .kpi-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 10px;
        text-align: center;
        margin: 0.5rem 0;
    }
    .kpi-number {
        font-size: 2.5rem;
        font-weight: bold;
        margin-bottom: 0.5rem;
    }
    .kpi-label {
        font-size: 1rem;
        opacity: 0.9;
    }
    .report-card {
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        background-color: #f9f9f9;
    }
    .severity-critical { color: #dc3545; font-weight: bold; }
    .severity-high { color: #fd7e14; font-weight: bold; }
    .severity-medium { color: #ffc107; font-weight: bold; }
    .severity-low { color: #28a745; font-weight: bold; }
    .stSelectbox > div > div { background-color: #f0f2f6; }
</style>
""", unsafe_allow_html=True)

@st.cache_data
def load_reports_cached():
    """Load reports with caching"""
    try:
        loader = ReportLoader()
        reports = loader.load_reports("reports")
        
        # Display any loading errors
        if hasattr(loader, 'errors') and loader.errors:
            with st.expander("⚠️ Report Loading Issues", expanded=True):
                st.error("**Issues found while loading reports:**")
                for error in loader.errors:
                    st.error(f"• {error}")
                st.info("💡 **Tip:** Valid reports will still be displayed below. Please fix the problematic files and refresh the page.")
                
                # Add helpful guidance
                st.markdown("""
                **Common issues:**
                - Invalid JSON syntax (missing commas, brackets)
                - Missing required fields (target, scan_date, subdomains, open_ports, vulnerabilities)
                - Incorrect data types (strings instead of arrays, etc.)
                """)
                
                if st.button("🔄 Refresh Reports", key="refresh_after_error"):
                    st.cache_data.clear()
                    st.rerun()
        
        return reports
    except Exception as e:
        st.error(f"Error loading reports: {str(e)}")
        return []

def initialize_components():
    """Initialize all components"""
    if 'analytics' not in st.session_state:
        st.session_state.analytics = ReportAnalytics()
    if 'ai_analyzer' not in st.session_state:
        try:
            st.session_state.ai_analyzer = AIAnalyzer()
        except Exception:
            st.session_state.ai_analyzer = type('DummyAI', (), {
                'is_enabled': lambda: False,
                'validate_api_key': lambda: False,
                'generate_summary': lambda self, report: None,
                'check_api_key_format': lambda: (False, "AI analyzer not available")
            })()

def render_kpi_cards(reports):
    """Render clean KPI cards"""
    if not reports:
        st.info("📊 No data available - add reports to see KPIs")
        return
    
    analytics = st.session_state.analytics
    kpis = analytics.calculate_kpis(reports)
    
    st.markdown("### 📊 Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-number">{kpis.get('total_reports', 0)}</div>
            <div class="kpi-label">Reports Analyzed</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-number">{kpis.get('total_subdomains', 0)}</div>
            <div class="kpi-label">Unique Subdomains</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        avg_ports = kpis.get('avg_open_ports', 0)
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-number">{avg_ports:.1f}</div>
            <div class="kpi-label">Avg Open Ports</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-number">{kpis.get('total_vulnerabilities', 0)}</div>
            <div class="kpi-label">Total Vulnerabilities</div>
        </div>
        """, unsafe_allow_html=True)

def render_single_report_view(report):
    """Render detailed view for a single report"""
    target = report.get('target', 'Unknown')
    scan_date = report.get('scan_date', 'Unknown')
    
    st.markdown(f"## 🎯 {target}")
    st.markdown(f"**Scan Date:** {scan_date}")
    
    # Quick stats
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Subdomains", len(report.get('subdomains', [])))
    with col2:
        st.metric("Open Ports", len(report.get('open_ports', {})))
    with col3:
        st.metric("Vulnerabilities", len(report.get('vulnerabilities', [])))
    
    # Tabs for organized content
    tab1, tab2, tab3, tab4 = st.tabs(["🌐 Subdomains", "🔌 Open Ports", "🚨 Vulnerabilities", "🤖 AI Analysis"])
    
    with tab1:
        subdomains = report.get('subdomains', [])
        if subdomains:
            st.write(f"**Found {len(subdomains)} subdomains:**")
            
            # Display in columns for better readability
            cols = st.columns(3)
            for i, subdomain in enumerate(subdomains):
                with cols[i % 3]:
                    st.write(f"• {subdomain}")
        else:
            st.info("No subdomains found")
    
    with tab2:
        open_ports = report.get('open_ports', {})
        if open_ports:
            st.write(f"**Found {len(open_ports)} open ports:**")
            
            # Create a clean table
            port_data = []
            for port, service in open_ports.items():
                port_data.append({
                    'Port': port,
                    'Service': service or 'Unknown',
                    'Risk': 'High' if port in ['22', '3389', '1433', '3306'] else 'Medium' if port in ['21', '23', '25'] else 'Low'
                })
            
            if port_data:
                # Option 1: Interactive Plotly table (PyArrow alternative)
                use_interactive_tables = st.checkbox("Use Interactive Tables", value=False, key="interactive_ports")
                
                if use_interactive_tables:
                    # Advanced interactive table with sorting, filtering
                    import plotly.graph_objects as go
                    
                    # Color code the risk levels
                    colors = []
                    for item in port_data:
                        if item['Risk'] == 'High':
                            colors.append('#ff4444')  # Red
                        elif item['Risk'] == 'Medium':
                            colors.append('#ffaa00')  # Orange
                        else:
                            colors.append('#44ff44')  # Green
                    
                    fig = go.Figure(data=[go.Table(
                        header=dict(
                            values=['Port', 'Service', 'Risk Level'],
                            fill_color='lightblue',
                            align='left',
                            font=dict(size=14, color='black'),
                            line_color='darkslategray',
                            line_width=1
                        ),
                        cells=dict(
                            values=[
                                [item['Port'] for item in port_data],
                                [item['Service'] for item in port_data],
                                [f"{item['Risk']}" for item in port_data]
                            ],
                            fill_color=[['white']*len(port_data), ['white']*len(port_data), colors],
                            align='left',
                            font=dict(size=12),
                            line_color='darkslategray',
                            line_width=1,
                            height=30
                        )
                    )])
                    
                    fig.update_layout(
                        title="Interactive Port Analysis - Hover for Details",
                        height=max(300, len(port_data) * 35 + 100),
                        margin=dict(l=0, r=0, t=50, b=0),
                        hoverlabel=dict(
                            bgcolor="white",
                            font_size=12,
                            font_family="Arial"
                        )
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    # Option 2: Clean markdown table (current approach)
                    st.markdown("| Port | Service | Risk Level |")
                    st.markdown("|------|---------|------------|")
                    for port_info in port_data:
                        risk_color = "🔴" if port_info['Risk'] == 'High' else "🟡" if port_info['Risk'] == 'Medium' else "🟢"
                        st.markdown(f"| {port_info['Port']} | {port_info['Service']} | {risk_color} {port_info['Risk']} |")
        else:
            st.info("No open ports found")
    
    with tab3:
        vulnerabilities = report.get('vulnerabilities', [])
        if vulnerabilities:
            st.write(f"**Found {len(vulnerabilities)} vulnerabilities:**")
            
            # Group by severity
            severity_groups = {'critical': [], 'high': [], 'medium': [], 'low': []}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'low').lower()
                if severity in severity_groups:
                    severity_groups[severity].append(vuln)
                else:
                    severity_groups['low'].append(vuln)
            
            # Display by severity
            for severity, vulns in severity_groups.items():
                if vulns:
                    severity_icons = {
                        'critical': '🔴',
                        'high': '🟠',
                        'medium': '🟡',
                        'low': '🟢'
                    }
                    
                    st.markdown(f"**{severity_icons[severity]} {severity.title()} Severity ({len(vulns)})**")
                    
                    for vuln in vulns:
                        with st.expander(f"{vuln.get('title', 'Unknown Vulnerability')}", expanded=False):
                            st.write(f"**Description:** {vuln.get('description', 'No description available')}")
                            st.write(f"**Affected Service:** {vuln.get('affected_service', 'Unknown')}")
                            
                            # Enhanced CVE display with research links
                            if vuln.get('cve_id'):
                                cve_id = vuln.get('cve_id')
                                st.write(f"**CVE ID:** `{cve_id}`")
                                
                                # Use the enhanced CVE linking function
                                render_cve_links(cve_id)
                            else:
                                st.info("💡 No CVE ID assigned to this vulnerability")
        else:
            st.info("No vulnerabilities found")
    
    with tab4:
        render_ai_analysis(report)

def render_ai_analysis(report):
    """Render AI analysis section"""
    if not st.session_state.ai_analyzer.is_enabled():
        st.warning("⚠️ AI analysis not available")
        st.info("""
        **To enable AI analysis:**
        1. Get an API key from [OpenRouter.ai](https://openrouter.ai)
        2. Enter it in the sidebar
        3. Generate AI summaries for threat analysis
        """)
        return
    
    # Check for existing summary (from cache or report)
    cached_summary = get_cached_ai_summary(report)
    existing_summary = report.get('ai_summary') or cached_summary
    
    if existing_summary:
        st.success("✅ AI Analysis Available")
        st.markdown("### 🎯 AI Threat Assessment")
        st.markdown(existing_summary)
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔄 Regenerate Analysis", key=f"regen_{report.get('target', 'unknown')}"):
                with st.spinner("Regenerating AI analysis..."):
                    try:
                        # Clear existing cache first
                        cache = load_ai_cache()
                        cache_key = get_report_cache_key(report)
                        if cache_key in cache:
                            del cache[cache_key]
                            save_ai_cache(cache)
                        
                        # Generate new summary
                        summary = st.session_state.ai_analyzer.generate_summary(report)
                        if summary and summary.strip():
                            cache_ai_summary(report, summary)
                            st.success("✅ Analysis regenerated!")
                            st.rerun()
                        else:
                            st.error("❌ Failed to generate analysis - empty response")
                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")
        
        with col2:
            if st.button("🗑️ Clear Analysis", key=f"clear_{report.get('target', 'unknown')}"):
                # Remove from cache
                cache = load_ai_cache()
                cache_key = get_report_cache_key(report)
                if cache_key in cache:
                    del cache[cache_key]
                    save_ai_cache(cache)
                st.success("✅ Analysis cleared!")
                st.rerun()
    else:
        st.info("💡 No AI analysis yet")
        # Check if AI is properly configured
        if not hasattr(st.session_state, 'ai_analyzer') or not st.session_state.ai_analyzer.is_enabled():
            st.warning("⚠️ AI analysis requires a valid API key. Please configure it in the sidebar.")
            return
        
        if st.button("🧠 Generate AI Analysis", key=f"gen_{report.get('target', 'unknown')}"):
            with st.spinner("Generating AI threat analysis..."):
                try:
                    # Store debug info
                    if 'ai_debug' not in st.session_state:
                        st.session_state.ai_debug = {}
                    
                    st.session_state.ai_debug['last_attempt'] = f"Generating for {report.get('target', 'unknown')}"
                    
                    summary = st.session_state.ai_analyzer.generate_summary(report)
                    
                    if summary and summary.strip():
                        # Cache the summary
                        cache_ai_summary(report, summary)
                        st.session_state.ai_debug['last_result'] = "Success - Cached"
                        st.success("✅ Analysis generated and cached!")
                        st.rerun()
                    else:
                        st.session_state.ai_debug['last_result'] = "Empty summary returned"
                        st.error("❌ Failed to generate analysis - empty response")
                        st.info("""
                        **Possible causes:**
                        - API key may be invalid or expired
                        - Insufficient credits in OpenRouter account
                        - Network connectivity issues
                        - API service temporarily unavailable
                        
                        **Try:**
                        - Verify your API key in the sidebar
                        - Check your OpenRouter account balance
                        - Try again in a few moments
                        """)
                        
                except Exception as e:
                    st.session_state.ai_debug['last_error'] = str(e)
                    st.error(f"❌ Error: {str(e)}")
        
        # Show AI debug info
        if 'ai_debug' in st.session_state:
            with st.expander("🔍 AI Debug Info"):
                for key, value in st.session_state.ai_debug.items():
                    st.write(f"{key}: {value}")

def render_multi_report_view(reports):
    """Render comparison view for multiple reports"""
    st.markdown("## 📊 Multi-Report Analysis")
    st.info(f"Analyzing {len(reports)} reports together")
    
    # Comparison table
    st.markdown("### 📋 Report Comparison")
    
    comparison_data = []
    for report in reports:
        comparison_data.append({
            'Target': report.get('target', 'Unknown'),
            'Scan Date': report.get('scan_date', 'Unknown'),
            'Subdomains': len(report.get('subdomains', [])),
            'Open Ports': len(report.get('open_ports', {})),
            'Vulnerabilities': len(report.get('vulnerabilities', [])),
            'Risk Level': calculate_risk_level(report)
        })
    
    # Display comparison table without PyArrow
    st.markdown("| Target | Scan Date | Subdomains | Open Ports | Vulnerabilities | Risk Level |")
    st.markdown("|--------|-----------|------------|------------|-----------------|------------|")
    for data in comparison_data:
        st.markdown(f"| {data['Target']} | {data['Scan Date']} | {data['Subdomains']} | {data['Open Ports']} | {data['Vulnerabilities']} | {data['Risk Level']} |")
    
    # Charts for comparison
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📊 Subdomains by Target")
        analytics = st.session_state.analytics
        subdomain_counts = analytics.get_subdomain_counts(reports)
        
        if subdomain_counts:
            try:
                fig = px.bar(
                    x=list(subdomain_counts.keys()),
                    y=list(subdomain_counts.values()),
                    title="Subdomains Found per Target",
                    labels={'x': 'Target', 'y': 'Subdomains'},
                    hover_data={'x': True, 'y': True}
                )
                fig.update_layout(
                    showlegend=False,
                    hovermode='closest'
                )
                fig.update_traces(
                    hovertemplate="<b>%{x}</b><br>Subdomains: %{y}<extra></extra>"
                )
                st.plotly_chart(fig, use_container_width=True, key="subdomain_chart")
            except Exception:
                st.bar_chart(subdomain_counts)
    
    with col2:
        st.markdown("### 🔌 Port Distribution")
        port_distribution = analytics.get_port_distribution(reports)
        
        if port_distribution:
            try:
                # Get top 8 ports
                top_ports = dict(list(port_distribution.items())[:8])
                fig = px.pie(
                    values=list(top_ports.values()),
                    names=[f"Port {p}" for p in top_ports.keys()],
                    title="Most Common Open Ports",
                    hover_data=['values']
                )
                fig.update_traces(
                    hovertemplate="<b>Port %{label}</b><br>Occurrences: %{value}<br>Percentage: %{percent}<extra></extra>"
                )
                fig.update_layout(
                    hovermode='closest'
                )
                st.plotly_chart(fig, use_container_width=True, key="port_chart")
            except Exception:
                st.write("**Top Ports:**")
                for port, count in list(port_distribution.items())[:5]:
                    st.write(f"Port {port}: {count} occurrences")
    
    # Vulnerability summary
    st.markdown("### 🚨 Vulnerability Summary")
    
    all_vulns = []
    for report in reports:
        vulns = report.get('vulnerabilities', [])
        for vuln in vulns:
            vuln_copy = vuln.copy()
            vuln_copy['target'] = report.get('target', 'Unknown')
            all_vulns.append(vuln_copy)
    
    if all_vulns:
        # Group by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in all_vulns:
            severity = vuln.get('severity', 'low').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts['low'] += 1
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("🔴 Critical", severity_counts['critical'])
        with col2:
            st.metric("🟠 High", severity_counts['high'])
        with col3:
            st.metric("🟡 Medium", severity_counts['medium'])
        with col4:
            st.metric("🟢 Low", severity_counts['low'])
        
        # Show top vulnerabilities
        if st.checkbox("Show detailed vulnerabilities"):
            # Display vulnerabilities table without PyArrow
            st.markdown("| Target | Title | Severity | Service | CVE Links |")
            st.markdown("|--------|-------|----------|---------|-----------|")
            for vuln in all_vulns:
                severity = vuln.get('severity', 'low').title()
                severity_icon = "🔴" if severity.lower() == 'critical' else "🟠" if severity.lower() == 'high' else "🟡" if severity.lower() == 'medium' else "🟢"
                
                # Create CVE links if CVE ID exists
                cve_links = ""
                if vuln.get('cve_id'):
                    cve_id = vuln.get('cve_id')
                    cve_links = f"[NVD](https://nvd.nist.gov/vuln/detail/{cve_id}) • [Details](https://www.cvedetails.com/cve/{cve_id}/) • [MITRE](https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id})"
                else:
                    cve_links = "N/A"
                
                st.markdown(f"| {vuln.get('target', 'Unknown')} | {vuln.get('title', 'Unknown')} | {severity_icon} {severity} | {vuln.get('affected_service', 'Unknown')} | {cve_links} |")
    else:
        st.success("✅ No vulnerabilities found across all reports")

def calculate_risk_level(report):
    """Calculate overall risk level for a report"""
    vulnerabilities = report.get('vulnerabilities', [])
    
    if not vulnerabilities:
        return "🟢 Low"
    
    severity_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    total_score = 0
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'low').lower()
        total_score += severity_scores.get(severity, 1)
    
    avg_score = total_score / len(vulnerabilities)
    
    if avg_score >= 3.5:
        return "🔴 Critical"
    elif avg_score >= 2.5:
        return "🟠 High"
    elif avg_score >= 1.5:
        return "🟡 Medium"
    else:
        return "🟢 Low"

def render_cve_links(cve_id):
    """Render clickable CVE links for research"""
    if not cve_id:
        return
    
    st.markdown("**🔗 CVE Research Links:**")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"🏛️ [NIST NVD](https://nvd.nist.gov/vuln/detail/{cve_id})")
        st.caption("Official US database")
    
    with col2:
        st.markdown(f"📊 [CVE Details](https://www.cvedetails.com/cve/{cve_id}/)")
        st.caption("Detailed statistics")
    
    with col3:
        st.markdown(f"🎯 [MITRE](https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id})")
        st.caption("Original CVE entry")
    
    with col4:
        st.markdown(f"🔍 [Exploit-DB](https://www.exploit-db.com/search?cve={cve_id})")
        st.caption("Known exploits")

def main():
    """Main application function"""
    
    # Initialize components
    initialize_components()
    
    # Header
    st.markdown('<h1 class="main-header">🛡️ AI Threat Hunting Dashboard</h1>', unsafe_allow_html=True)
    
    # Load reports
    reports = load_reports_cached()
    
    # Sidebar
    st.sidebar.header("🔍 Report Selection")
    
    if not reports:
        st.sidebar.error("❌ No reports found")
        st.error("⚠️ No reports found in the 'reports' directory.")
        st.info("""
        **To get started:**
        1. Add JSON report files to the 'reports' directory
        2. Refresh this page
        3. Reports will appear in the sidebar
        """)
        return
    
    # Report selection
    st.sidebar.success(f"✅ {len(reports)} reports available")
    
    # Single or multiple selection
    selection_mode = st.sidebar.radio(
        "Analysis Mode:",
        ["📋 Single Report", "📊 Compare Multiple"],
        help="Choose how to analyze your reports",
        key="analysis_mode_selector"
    )
    
    if selection_mode == "📋 Single Report":
        # Single report selection
        report_options = [f"{r.get('target', 'Unknown')} ({r.get('scan_date', 'Unknown')})" for r in reports]
        selected_report_idx = st.sidebar.selectbox(
            "Select a report:",
            range(len(reports)),
            format_func=lambda x: report_options[x],
            key="single_report_selector"
        )
        
        selected_reports = [reports[selected_report_idx]]
        
    elif selection_mode == "📊 Compare Multiple":
        # Multiple report selection
        st.sidebar.info("📊 Multi-Report Comparison Mode")
        all_targets = [r.get('target', 'Unknown') for r in reports]
        selected_targets = st.sidebar.multiselect(
            "Select targets to compare:",
            options=all_targets,
            default=all_targets[:min(len(all_targets), 3)],  # Default to first 3 to avoid overwhelming
            help="Choose which reports to include in the analysis",
            key="multi_report_selector"
        )
        
        selected_reports = [r for r in reports if r.get('target', 'Unknown') in selected_targets]
        
        if not selected_targets:
            st.sidebar.warning("⚠️ Please select at least one report to compare")
            selected_reports = []
    else:
        # Fallback - should not happen but ensures we have selected_reports
        selected_reports = [reports[0]] if reports else []
    
    # AI Configuration
    st.sidebar.markdown("---")
    st.sidebar.subheader("🤖 AI Configuration")
    
    # Load saved API key
    saved_api_key = load_api_key()
    current_api_key = saved_api_key or os.getenv('OPENROUTER_API_KEY', '')
    
    api_key_input = st.sidebar.text_input(
        "OpenRouter API Key:",
        value=current_api_key,
        type="password",
        help="Get your key from openrouter.ai (should start with 'sk-or-')",
        placeholder="sk-or-v1-..."
    )
    
    if api_key_input and not api_key_input.startswith('sk-or-'):
        st.sidebar.warning("⚠️ API key should start with 'sk-or-'")
        st.sidebar.info("💡 Get a free API key from [OpenRouter.ai](https://openrouter.ai/keys)")
    
    # Save API key checkbox
    save_key = st.sidebar.checkbox(
        "💾 Remember API key",
        value=bool(saved_api_key),
        help="Save API key locally for future sessions"
    )
    
    if api_key_input and api_key_input.strip():
        # Save API key if requested
        if save_key:
            save_api_key(api_key_input.strip())
        elif not save_key and saved_api_key:
            # Clear saved key if unchecked
            clear_api_key()
        
        os.environ['OPENROUTER_API_KEY'] = api_key_input.strip()
        try:
            # Create AI analyzer with the provided key
            st.session_state.ai_analyzer = AIAnalyzer(api_key=api_key_input.strip())
            
            # Persistent debug info in session state
            if 'debug_info' not in st.session_state:
                st.session_state.debug_info = {}
            
            st.session_state.debug_info['api_key_length'] = len(api_key_input.strip())
            st.session_state.debug_info['ai_enabled'] = st.session_state.ai_analyzer.is_enabled()
            
            if st.session_state.ai_analyzer.is_enabled():
                # Test API key validation
                col1, col2 = st.sidebar.columns(2)
                
                with col1:
                    if st.button("🧪 Test API"):
                        with st.spinner("Testing..."):
                            try:
                                # First check API key format
                                format_valid, format_msg = st.session_state.ai_analyzer.check_api_key_format()
                                if not format_valid:
                                    st.error(f"❌ {format_msg}")
                                    st.info("💡 Get your API key from [OpenRouter.ai](https://openrouter.ai/keys)")
                                    return
                                
                                # Then validate with API
                                is_valid = st.session_state.ai_analyzer.validate_api_key()
                                st.session_state.debug_info['api_validation'] = is_valid
                                if is_valid:
                                    st.success("✅ API key is valid!")
                                    # Also save the key if validation succeeds
                                    if save_key:
                                        save_api_key(api_key_input.strip())
                                        st.info("💾 API key saved successfully")
                                else:
                                    st.error("❌ API key validation failed!")
                                    st.info("💡 Make sure you have credits and the key is active")
                            except Exception as test_error:
                                st.session_state.debug_info['validation_error'] = str(test_error)
                                st.error(f"❌ Validation error: {str(test_error)}")
                
                with col2:
                    if st.button("🤖 Quick Test"):
                        with st.spinner("Testing AI..."):
                            try:
                                test_report = {
                                    "target": "test.com",
                                    "vulnerabilities": [{"severity": "high", "title": "Test vulnerability"}],
                                    "open_ports": {"80": "http"}
                                }
                                summary = st.session_state.ai_analyzer.generate_summary(test_report)
                                if summary:
                                    st.success("✅ AI Working!")
                                    st.session_state.debug_info['ai_test'] = "Success"
                                else:
                                    st.error("❌ AI Failed!")
                                    st.session_state.debug_info['ai_test'] = "Failed"
                            except Exception as ai_error:
                                st.error(f"❌ AI Error!")
                                st.session_state.debug_info['ai_test_error'] = str(ai_error)
            else:
                st.sidebar.warning("⚠️ AI analyzer not enabled")
        except Exception as e:
            st.session_state.debug_info['setup_error'] = str(e)
            st.sidebar.error(f"❌ AI setup failed: {str(e)}")
    
    # Show persistent debug info
    if 'debug_info' in st.session_state and st.session_state.debug_info:
        with st.sidebar.expander("🔍 Debug Info"):
            for key, value in st.session_state.debug_info.items():
                st.write(f"{key}: {value}")
    else:
        st.sidebar.info("💡 Enter API key to enable AI analysis")
    
    # AI Cache Management
    st.sidebar.markdown("---")
    st.sidebar.subheader("🧠 AI Cache")
    
    cache = load_ai_cache()
    cache_count = len(cache)
    st.sidebar.write(f"📊 Cached analyses: {cache_count}")
    
    if cache_count > 0:
        if st.sidebar.button("🗑️ Clear All Cache"):
            save_ai_cache({})
            st.sidebar.success("✅ Cache cleared!")
            st.rerun()
    
    # CVE Research Tool
    st.sidebar.markdown("---")
    st.sidebar.subheader("🔍 CVE Research")
    
    cve_search = st.sidebar.text_input(
        "Quick CVE Lookup:",
        placeholder="e.g., CVE-2023-1234",
        help="Enter a CVE ID to get research links"
    )
    
    if cve_search and cve_search.strip():
        cve_id = cve_search.strip().upper()
        if cve_id.startswith('CVE-'):
            st.sidebar.markdown("**🔗 Research Links:**")
            st.sidebar.markdown(f"🏛️ [NIST NVD](https://nvd.nist.gov/vuln/detail/{cve_id})")
            st.sidebar.markdown(f"📊 [CVE Details](https://www.cvedetails.com/cve/{cve_id}/)")
            st.sidebar.markdown(f"🎯 [MITRE](https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id})")
            st.sidebar.markdown(f"🔍 [Exploit-DB](https://www.exploit-db.com/search?cve={cve_id})")
        else:
            st.sidebar.warning("⚠️ Please enter a valid CVE ID (e.g., CVE-2023-1234)")
    
    # Refresh button
    if st.sidebar.button("🔄 Refresh Data"):
        # Clear all caches
        st.cache_data.clear()
        
        # Clear session state to force reload
        if 'analytics' in st.session_state:
            del st.session_state.analytics
        if 'ai_analyzer' in st.session_state:
            del st.session_state.ai_analyzer
            
        st.success("✅ Data refreshed! Reloading...")
        st.rerun()
    
    # Main content
    if not selected_reports:
        st.warning("⚠️ No reports selected. Choose reports from the sidebar.")
        return
    
    # Render KPIs
    render_kpi_cards(selected_reports)
    
    st.markdown("---")
    
    # Render appropriate view
    if len(selected_reports) == 1:
        render_single_report_view(selected_reports[0])
    else:
        render_multi_report_view(selected_reports)
    
    # CVE Summary Section
    if len(selected_reports) > 0:
        st.markdown("---")
        st.subheader("🎯 CVE Summary")
        
        # Collect all CVEs from selected reports
        all_cves = []
        for report in selected_reports:
            for vuln in report.get('vulnerabilities', []):
                if vuln.get('cve_id'):
                    all_cves.append({
                        'cve_id': vuln.get('cve_id'),
                        'target': report.get('target', 'Unknown'),
                        'title': vuln.get('title', 'Unknown'),
                        'severity': vuln.get('severity', 'low')
                    })
        
        if all_cves:
            st.write(f"**Found {len(all_cves)} CVEs across selected reports:**")
            
            # Group by severity
            cve_by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
            for cve in all_cves:
                severity = cve['severity'].lower()
                if severity in cve_by_severity:
                    cve_by_severity[severity].append(cve)
                else:
                    cve_by_severity['low'].append(cve)
            
            # Display by severity
            for severity, cves in cve_by_severity.items():
                if cves:
                    severity_icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
                    icon = severity_icons.get(severity, '⚪')
                    
                    with st.expander(f"{icon} {severity.title()} Severity CVEs ({len(cves)})", expanded=severity in ['critical', 'high']):
                        for cve in cves:
                            col1, col2 = st.columns([2, 1])
                            with col1:
                                st.write(f"**{cve['cve_id']}** - {cve['title']} ({cve['target']})")
                            with col2:
                                # Quick research links
                                st.markdown(f"[NVD](https://nvd.nist.gov/vuln/detail/{cve['cve_id']}) • [Details](https://www.cvedetails.com/cve/{cve['cve_id']}/)")
        else:
            st.success("✅ No CVEs found in selected reports")
    
    # Footer
    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        st.caption("*AI Threat Hunting Dashboard - Enhanced with CVE Research*")
    with col2:
        ai_status = "✅" if st.session_state.ai_analyzer.is_enabled() else "❌"
        cve_count = len([v for r in selected_reports for v in r.get('vulnerabilities', []) if v.get('cve_id')])
        st.caption(f"Reports: {len(selected_reports)} | CVEs: {cve_count} | AI: {ai_status}")

if __name__ == "__main__":
    main()