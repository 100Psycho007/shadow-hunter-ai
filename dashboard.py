#!/usr/bin/env python3
"""
AI Threat Hunting Dashboard
A Streamlit-based cybersecurity analytics and visualization tool
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import os
import sys
import requests
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from loader import ReportLoader
from analytics import ReportAnalytics
from ai import AIAnalyzer

# Page configuration
st.set_page_config(
    page_title="AI Threat Hunting Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .kpi-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .kpi-number {
        font-size: 2rem;
        font-weight: bold;
        color: #1f77b4;
    }
    .kpi-label {
        font-size: 0.9rem;
        color: #666;
        margin-top: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)

def initialize_session_state():
    """Initialize session state variables"""
    if 'reports' not in st.session_state:
        st.session_state.reports = []
    if 'filtered_reports' not in st.session_state:
        st.session_state.filtered_reports = []
    if 'loader' not in st.session_state:
        st.session_state.loader = ReportLoader()
    if 'analytics' not in st.session_state:
        st.session_state.analytics = ReportAnalytics()
    if 'ai_analyzer' not in st.session_state:
        st.session_state.ai_analyzer = AIAnalyzer()
    if 'ai_loading_states' not in st.session_state:
        st.session_state.ai_loading_states = {}
    if 'selected_report_idx' not in st.session_state:
        st.session_state.selected_report_idx = None
    if 'show_sample' not in st.session_state:
        st.session_state.show_sample = False
    if 'force_reload' not in st.session_state:
        st.session_state.force_reload = False

def load_reports():
    """Load reports from the reports directory"""
    try:
        reports_dir = "reports"
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
            st.warning(f"Created {reports_dir} directory. Please add your JSON report files there.")
            return []
        
        # Debug: Show what files are found
        json_files = [f for f in os.listdir(reports_dir) if f.lower().endswith('.json')]
        logger.info(f"Found JSON files: {json_files}")
        
        if not json_files:
            st.info("📁 No JSON files found in reports directory. Add some JSON report files to get started.")
            return []
        
        # Ensure loader is initialized
        if 'loader' not in st.session_state:
            st.session_state.loader = ReportLoader()
            
        reports = st.session_state.loader.load_reports(reports_dir)
        logger.info(f"Successfully loaded {len(reports)} reports")
        
        if not reports and json_files:
            st.warning("⚠️ JSON files found but no valid reports loaded. Check file format and schema.")
        elif reports:
            st.success(f"✅ Successfully loaded {len(reports)} reports from {len(json_files)} files")
        
        return reports
    except Exception as e:
        logger.error(f"Error loading reports: {str(e)}")
        st.error(f"Error loading reports: {str(e)}")
        return []

def render_header():
    """Render the main application header"""
    st.markdown('<h1 class="main-header">🛡️ AI Threat Hunting Dashboard</h1>', unsafe_allow_html=True)
    st.markdown("---")

def render_sidebar():
    """Render the sidebar with filters and controls"""
    st.sidebar.header("🔍 Filters & Controls")
    
    # Get all available targets for filtering
    all_targets = []
    if st.session_state.reports:
        all_targets = sorted(list(set(report.get('target', '') for report in st.session_state.reports if report.get('target'))))
    
    # Target Filtering
    st.sidebar.subheader("🎯 Target Filtering")
    if all_targets:
        selected_targets = st.sidebar.multiselect(
            "Select targets to include:",
            options=all_targets,
            default=all_targets,
            key="target_filter"
        )
    else:
        selected_targets = []
        st.sidebar.info("No targets available")
    
    # Date Range Filtering
    st.sidebar.subheader("📅 Date Range")
    if st.session_state.reports:
        # Get date range from reports
        dates = []
        for report in st.session_state.reports:
            scan_date = report.get('scan_date')
            if scan_date:
                try:
                    # Try to parse the date
                    if isinstance(scan_date, str):
                        date_obj = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))
                    else:
                        date_obj = scan_date
                    dates.append(date_obj.date())
                except:
                    continue
        
        if dates:
            min_date = min(dates)
            max_date = max(dates)
            
            date_range = st.sidebar.date_input(
                "Select date range:",
                value=(min_date, max_date),
                min_value=min_date,
                max_value=max_date,
                key="date_filter"
            )
        else:
            date_range = None
            st.sidebar.info("No valid dates found in reports")
    else:
        date_range = None
        st.sidebar.info("No reports available for date filtering")
    
    # Keyword Search
    st.sidebar.subheader("🔍 Keyword Search")
    keyword_search = st.sidebar.text_input(
        "Search in targets, subdomains, or vulnerabilities:",
        placeholder="Enter keywords...",
        key="keyword_filter"
    )
    
    # AI Configuration and Features
    st.sidebar.subheader("🤖 AI Features")
    
    # AI API Key Configuration
    current_api_key = os.getenv('OPENROUTER_API_KEY', '')
    api_key_input = st.sidebar.text_input(
        "OpenRouter API Key:",
        value=current_api_key,
        type="password",
        help="Enter your OpenRouter API key to enable AI threat analysis"
    )
    
    if api_key_input and api_key_input != current_api_key:
        os.environ['OPENROUTER_API_KEY'] = api_key_input
        # Reinitialize AI analyzer with new key
        st.session_state.ai_analyzer = AIAnalyzer(api_key=api_key_input)
        st.sidebar.success("✅ API key updated!")
    
    show_ai_summaries = st.sidebar.checkbox(
        "Show AI summaries (when available)",
        value=True,
        key="ai_toggle"
    )
    
    if st.session_state.ai_analyzer.is_enabled():
        st.sidebar.success("✅ AI functionality enabled")
        if st.sidebar.button("🧠 Generate AI Summaries"):
            if st.session_state.filtered_reports:
                with st.spinner("Generating AI summaries..."):
                    for report in st.session_state.filtered_reports:
                        if not report.get('ai_summary'):
                            summary = st.session_state.ai_analyzer.generate_summary(report)
                            if summary:
                                report['ai_summary'] = summary
                st.sidebar.success("AI summaries generated!")
                st.rerun()
            else:
                st.sidebar.warning("No reports available for AI analysis")
    else:
        st.sidebar.warning("⚠️ AI disabled - enter OpenRouter API key above")
        st.sidebar.info("Get your API key at: https://openrouter.ai/")
    
    # Apply Filters
    st.sidebar.markdown("---")
    
    # Auto-apply filters when any filter changes
    filters = {
        'selected_targets': selected_targets,
        'date_range': date_range,
        'keyword_search': keyword_search.lower().strip() if keyword_search else '',
        'show_ai_summaries': show_ai_summaries
    }
    
    # Apply filters to reports
    try:
        st.session_state.filtered_reports = st.session_state.analytics.filter_reports(
            st.session_state.reports, 
            filters
        )
    except Exception as e:
        logger.error(f"Error filtering reports: {str(e)}")
        st.session_state.filtered_reports = st.session_state.reports
    
    # Show filter summary
    total_reports = len(st.session_state.reports)
    filtered_count = len(st.session_state.filtered_reports)
    
    if filtered_count < total_reports:
        st.sidebar.info(f"📊 Showing {filtered_count} of {total_reports} reports")
    
    # Refresh button
    if st.sidebar.button("🔄 Refresh Data"):
        st.session_state.reports = load_reports()
        st.session_state.filtered_reports = st.session_state.reports
        st.rerun()
    
    # Debug information (expandable)
    with st.sidebar.expander("🔧 Debug Info"):
        st.write(f"Total reports loaded: {len(st.session_state.reports)}")
        st.write(f"Filtered reports: {len(st.session_state.filtered_reports)}")
        st.write(f"Reports directory exists: {os.path.exists('reports')}")
        if os.path.exists('reports'):
            json_files = [f for f in os.listdir('reports') if f.lower().endswith('.json')]
            st.write(f"JSON files found: {len(json_files)}")
            if json_files:
                st.write("Files:", json_files)

def render_kpi_cards():
    """Render KPI summary cards with dynamic data"""
    st.subheader("📊 Key Performance Indicators")
    
    # Calculate KPIs from filtered reports
    reports = st.session_state.filtered_reports
    kpis = st.session_state.analytics.calculate_kpis(reports)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-number">{kpis.get('total_reports', 0)}</div>
            <div class="kpi-label">Total Reports</div>
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
            <div class="kpi-label">Average Open Ports</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-number">{kpis.get('total_vulnerabilities', 0)}</div>
            <div class="kpi-label">Total Vulnerabilities</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Show zero-state message if no reports
    if kpis.get('total_reports', 0) == 0:
        st.info("📁 No reports found. Add JSON report files to the 'reports' directory to get started.")
        
        # Show sample data button
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📄 View Sample Report Format"):
                st.session_state.show_sample = True
        with col2:
            if st.button("🔄 Refresh Data"):
                st.session_state.reports = load_reports()
                st.session_state.filtered_reports = st.session_state.reports
                st.rerun()
        
        # Show sample format if requested
        if st.session_state.get('show_sample', False):
            st.subheader("📋 Sample Report Format")
            sample_report = {
                "target": "example.com",
                "scan_date": "2025-01-15",
                "subdomains": ["www.example.com", "api.example.com", "admin.example.com"],
                "open_ports": {"22": "ssh", "80": "http", "443": "https", "3306": "mysql"},
                "vulnerabilities": [
                    {
                        "severity": "high",
                        "title": "SQL Injection",
                        "description": "Potential SQL injection vulnerability in login form",
                        "affected_service": "http",
                        "cve_id": "CVE-2023-1234"
                    }
                ],
                "ai_summary": None
            }
            st.json(sample_report)
            if st.button("❌ Hide Sample"):
                st.session_state.show_sample = False
                st.rerun()

def render_subdomain_chart():
    """Render the subdomain distribution bar chart"""
    reports = st.session_state.filtered_reports
    
    if not reports:
        st.info("📊 No data available for subdomain chart")
        return
    
    try:
        # Get subdomain counts per target
        subdomain_counts = st.session_state.analytics.get_subdomain_counts(reports)
        
        if not subdomain_counts:
            st.info("📊 No subdomain data found")
            return
        
        # Prepare data for plotting
        targets = list(subdomain_counts.keys())
        counts = list(subdomain_counts.values())
        
        # Handle cases with many targets by limiting display
        max_targets = 20
        if len(targets) > max_targets:
            # Sort by count and take top targets
            sorted_data = sorted(zip(targets, counts), key=lambda x: x[1], reverse=True)
            targets = [item[0] for item in sorted_data[:max_targets]]
            counts = [item[1] for item in sorted_data[:max_targets]]
            
            # Add info about truncation
            remaining = len(subdomain_counts) - max_targets
            st.info(f"📊 Showing top {max_targets} targets. {remaining} more targets available.")
        
        # Create bar chart
        fig = px.bar(
            x=targets,
            y=counts,
            title="Subdomain Distribution by Target",
            labels={'x': 'Target', 'y': 'Number of Subdomains'},
            color=counts,
            color_continuous_scale='Blues'
        )
        
        # Update layout for better readability
        fig.update_layout(
            xaxis_tickangle=-45,
            height=400,
            showlegend=False,
            xaxis_title="Target",
            yaxis_title="Number of Subdomains"
        )
        
        # Show the chart
        st.plotly_chart(fig, use_container_width=True)
        
    except Exception as e:
        st.error(f"Error creating subdomain chart: {str(e)}")
        logger.error(f"Subdomain chart error: {str(e)}")
        # Show fallback data
        st.write("**Subdomain Counts:**")
        for target, count in subdomain_counts.items():
            st.write(f"- {target}: {count} subdomains")

def render_ports_chart():
    """Render the open ports distribution pie chart"""
    reports = st.session_state.filtered_reports
    
    if not reports:
        st.info("🥧 No data available for ports chart")
        return
    
    try:
        # Get port distribution across all reports
        port_distribution = st.session_state.analytics.get_port_distribution(reports)
        
        if not port_distribution:
            st.info("🥧 No port data found")
            return
        
        # Prepare data for plotting
        ports = list(port_distribution.keys())
        counts = list(port_distribution.values())
        
        # Group less common ports into "Other" category for readability
        min_count_threshold = max(1, max(counts) * 0.05)  # 5% of max count
        max_individual_ports = 10
        
        # Sort by count descending
        sorted_data = sorted(zip(ports, counts), key=lambda x: x[1], reverse=True)
        
        # Separate major ports from minor ones
        major_ports = []
        major_counts = []
        other_count = 0
        
        for i, (port, count) in enumerate(sorted_data):
            if i < max_individual_ports and count >= min_count_threshold:
                # Add service name if available from sample data
                port_label = f"Port {port}"
                # Try to get service name from first report that has this port
                for report in reports:
                    open_ports = report.get('open_ports', {})
                    if port in open_ports and open_ports[port]:
                        service = open_ports[port]
                        port_label = f"Port {port} ({service})"
                        break
                
                major_ports.append(port_label)
                major_counts.append(count)
            else:
                other_count += count
        
        # Add "Other" category if there are grouped ports
        if other_count > 0:
            major_ports.append("Other")
            major_counts.append(other_count)
        
        # Create pie chart
        fig = px.pie(
            values=major_counts,
            names=major_ports,
            title="Open Ports Distribution"
        )
        
        # Update layout for better readability
        fig.update_layout(
            height=400,
            showlegend=True,
            legend=dict(
                orientation="v",
                yanchor="middle",
                y=0.5,
                xanchor="left",
                x=1.01
            )
        )
        
        # Update traces for better display
        fig.update_traces(
            textposition='inside',
            textinfo='percent+label',
            hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
        )
        
        # Show the chart
        st.plotly_chart(fig, use_container_width=True)
        
    except Exception as e:
        st.error(f"Error creating ports chart: {str(e)}")
        logger.error(f"Ports chart error: {str(e)}")
        # Show fallback data
        st.write("**Port Distribution:**")
        for port, count in list(port_distribution.items())[:10]:
            st.write(f"- Port {port}: {count} occurrences")

def render_timeline_chart():
    """Render the timeline chart for report activity"""
    reports = st.session_state.filtered_reports
    
    if not reports:
        st.info("📅 No data available for timeline chart")
        return
    
    try:
        # Get timeline data
        timeline_data = st.session_state.analytics.get_timeline_data(reports)
        
        if not timeline_data:
            st.info("📅 No timeline data found")
            return
        
        # Prepare data for plotting
        dates = [item[0] for item in timeline_data]
        counts = [item[1] for item in timeline_data]
        
        # Convert date strings to datetime objects for better plotting
        date_objects = []
        for date_str in dates:
            try:
                date_obj = datetime.strptime(date_str, '%Y-%m-%d')
                date_objects.append(date_obj)
            except ValueError:
                # Fallback to string if parsing fails
                date_objects.append(date_str)
        
        # Create line chart for timeline
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=date_objects,
            y=counts,
            mode='lines+markers',
            name='Reports',
            line=dict(color='#1f77b4', width=3),
            marker=dict(size=8, color='#1f77b4'),
            hovertemplate='<b>Date:</b> %{x}<br><b>Reports:</b> %{y}<extra></extra>'
        ))
        
        # Update layout
        fig.update_layout(
            title="Report Activity Timeline",
            xaxis_title="Date",
            yaxis_title="Number of Reports",
            height=400,
            showlegend=False,
            hovermode='x unified'
        )
        
        # Format x-axis for better date display
        fig.update_xaxes(
            tickformat='%Y-%m-%d',
            tickangle=-45
        )
        
        # Ensure y-axis shows integers only
        fig.update_yaxes(
            dtick=1 if max(counts) <= 10 else None,
            tickformat='d'
        )
        
        # Show the chart
        st.plotly_chart(fig, use_container_width=True)
        
        # Show summary statistics
        total_days = len(timeline_data)
        total_reports = sum(counts)
        avg_reports_per_day = total_reports / total_days if total_days > 0 else 0
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Active Days", total_days)
        with col2:
            st.metric("Total Reports", total_reports)
        with col3:
            st.metric("Avg Reports/Day", f"{avg_reports_per_day:.1f}")
        
    except Exception as e:
        st.error(f"Error creating timeline chart: {str(e)}")
        logger.error(f"Timeline chart error: {str(e)}")
        # Show fallback data
        st.write("**Timeline Data:**")
        for date_str, count in timeline_data:
            st.write(f"- {date_str}: {count} reports")

def render_reports_table():
    """Render the detailed reports table with summary information and sorting"""
    st.subheader("📋 Detailed Report Table")
    
    reports = st.session_state.filtered_reports
    
    # Handle empty states with comprehensive guidance
    if not reports:
        if not st.session_state.reports:
            # No reports at all - provide detailed setup guidance
            st.info("📁 No reports found in the reports directory.")
            
            # Check if reports directory exists
            reports_dir = "reports"
            if not os.path.exists(reports_dir):
                st.warning(f"⚠️ The '{reports_dir}' directory does not exist. It will be created automatically when you refresh.")
            
            # Provide comprehensive setup instructions
            st.markdown("""
            ### 🚀 Getting Started
            
            **To add reconnaissance reports:**
            1. **Create report files:** Place your JSON reconnaissance report files in the `reports/` directory
            2. **Follow the schema:** Ensure your JSON files include these fields:
               ```json
               {
                 "target": "example.com",
                 "scan_date": "2025-01-02",
                 "subdomains": ["sub1.example.com", "sub2.example.com"],
                 "open_ports": {"80": "http", "443": "https"},
                 "vulnerabilities": [
                   {
                     "severity": "medium",
                     "title": "Example Vulnerability",
                     "description": "Description here",
                     "affected_service": "http"
                   }
                 ]
               }
               ```
            3. **Refresh data:** Click the '🔄 Refresh Data' button in the sidebar
            
            **Sample Data:** Check the `reports/sample.json` file for a complete example.
            """)
            
            # Show sample data button
            if st.button("📄 View Sample Report Format"):
                sample_report = {
                    "target": "example.com",
                    "scan_date": "2025-01-02",
                    "subdomains": ["api.example.com", "admin.example.com", "mail.example.com"],
                    "open_ports": {"22": "ssh", "80": "http", "443": "https", "3306": "mysql"},
                    "vulnerabilities": [
                        {
                            "severity": "high",
                            "title": "SQL Injection",
                            "description": "Potential SQL injection vulnerability in login form",
                            "affected_service": "http",
                            "cve_id": "CVE-2023-1234"
                        },
                        {
                            "severity": "medium", 
                            "title": "Outdated Software",
                            "description": "Web server running outdated version",
                            "affected_service": "https"
                        }
                    ],
                    "ai_summary": None
                }
                st.json(sample_report)
        else:
            # Reports exist but none match current filters
            st.warning("🔍 No reports match the current filters.")
            
            # Provide filter adjustment guidance
            st.markdown("""
            ### 💡 Try These Solutions:
            - **Clear target filters:** Select more or all targets in the sidebar
            - **Expand date range:** Adjust the date range to include more reports  
            - **Remove keyword search:** Clear the search box to see all reports
            - **Reset all filters:** Use broader filter criteria
            """)
            
            # Show current filter summary
            total_reports = len(st.session_state.reports)
            st.info(f"📊 {total_reports} total reports available, but none match current filters")
            
            # Quick reset filters button
            if st.button("🔄 Reset All Filters"):
                # Reset filters by clearing session state filter keys
                filter_keys = ['target_filter', 'date_filter', 'keyword_filter']
                for key in filter_keys:
                    if key in st.session_state:
                        del st.session_state[key]
                # Force refresh filtered reports
                st.session_state.filtered_reports = st.session_state.reports.copy()
                st.rerun()
        return
    
    try:
        # Validate reports data structure
        if not isinstance(reports, list):
            st.error("❌ Invalid reports data structure. Expected a list of report dictionaries.")
            return
        
        # Prepare table data with robust error handling
        table_data = []
        processing_errors = []
        
        for i, report in enumerate(reports):
            try:
                # Validate report structure
                if not isinstance(report, dict):
                    processing_errors.append(f"Report {i+1}: Invalid format (not a dictionary)")
                    continue
                
                # Extract basic information with fallbacks
                target = report.get('target', 'Unknown')
                if not isinstance(target, str):
                    target = str(target) if target is not None else 'Unknown'
                
                scan_date = report.get('scan_date', 'Unknown')
                
                # Count subdomains with error handling
                subdomains = report.get('subdomains', [])
                if isinstance(subdomains, list):
                    subdomain_count = len(subdomains)
                elif subdomains is None:
                    subdomain_count = 0
                else:
                    subdomain_count = 0
                    processing_errors.append(f"Report {i+1} ({target}): Invalid subdomains format")
                
                # Count open ports with error handling
                open_ports = report.get('open_ports', {})
                if isinstance(open_ports, dict):
                    ports_count = len(open_ports)
                elif open_ports is None:
                    ports_count = 0
                else:
                    ports_count = 0
                    processing_errors.append(f"Report {i+1} ({target}): Invalid open_ports format")
                
                # Count vulnerabilities with error handling
                vulnerabilities = report.get('vulnerabilities', [])
                if isinstance(vulnerabilities, list):
                    vuln_count = len(vulnerabilities)
                elif vulnerabilities is None:
                    vuln_count = 0
                else:
                    vuln_count = 0
                    processing_errors.append(f"Report {i+1} ({target}): Invalid vulnerabilities format")
                
                # Format date for display with error handling
                formatted_date = scan_date
                try:
                    if isinstance(scan_date, str) and scan_date != 'Unknown':
                        # Try multiple date formats
                        for date_format in ['%Y-%m-%d', '%Y/%m/%d', '%d-%m-%Y', '%d/%m/%Y']:
                            try:
                                parsed_date = datetime.strptime(scan_date, date_format)
                                formatted_date = parsed_date.strftime('%Y-%m-%d')
                                break
                            except ValueError:
                                continue
                        else:
                            # Try ISO format with timezone
                            try:
                                parsed_date = datetime.fromisoformat(scan_date.replace('Z', '+00:00'))
                                formatted_date = parsed_date.strftime('%Y-%m-%d')
                            except:
                                # Keep original format if all parsing fails
                                formatted_date = str(scan_date)
                except Exception as date_error:
                    formatted_date = str(scan_date)
                    processing_errors.append(f"Report {i+1} ({target}): Date parsing error - {str(date_error)}")
                
                table_data.append({
                    'Index': i,  # Keep track of original index for expansion
                    'Target': target,
                    'Scan Date': formatted_date,
                    'Subdomains': subdomain_count,
                    'Open Ports': ports_count,
                    'Vulnerabilities': vuln_count
                })
                
            except Exception as report_error:
                processing_errors.append(f"Report {i+1}: Processing error - {str(report_error)}")
                continue
        
        # Show processing errors if any
        if processing_errors:
            with st.expander(f"⚠️ Processing Warnings ({len(processing_errors)})", expanded=False):
                for error in processing_errors:
                    st.warning(error)
        
        # Check if we have any valid data to display
        if not table_data:
            st.error("❌ No valid report data could be processed. Please check your report file formats.")
            st.markdown("""
            **Common issues:**
            - Reports are not in valid JSON format
            - Required fields (target, scan_date) are missing
            - Data types don't match expected format (e.g., subdomains should be a list)
            """)
            return
        
        # Create DataFrame for display
        try:
            df = pd.DataFrame(table_data)
        except Exception as df_error:
            st.error(f"❌ Error creating data table: {str(df_error)}")
            logger.error(f"DataFrame creation error: {str(df_error)}")
            # Fallback to simple table display
            st.write("**Reports Summary:**")
            for i, data in enumerate(table_data):
                st.write(f"{i+1}. {data.get('Target', 'Unknown')} - {data.get('Scan Date', 'Unknown')}")
            return
        
        # Add sorting controls
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.write(f"Showing {len(table_data)} reports")
            if processing_errors:
                st.caption(f"⚠️ {len(processing_errors)} reports had processing warnings")
        
        with col2:
            sort_column = st.selectbox(
                "Sort by:",
                options=['Target', 'Scan Date', 'Subdomains', 'Open Ports', 'Vulnerabilities'],
                key="table_sort_column"
            )
            
            sort_ascending = st.checkbox("Ascending", value=True, key="table_sort_ascending")
        
        # Sort the DataFrame with error handling
        try:
            if sort_column in df.columns:
                df_sorted = df.sort_values(by=sort_column, ascending=sort_ascending)
            else:
                df_sorted = df
                st.warning(f"⚠️ Cannot sort by '{sort_column}' - column not found")
        except Exception as sort_error:
            st.warning(f"⚠️ Sorting error: {str(sort_error)}. Showing unsorted data.")
            df_sorted = df
        
        # Display the table with selection capability
        try:
            # Display the dataframe
            display_columns = ['Target', 'Scan Date', 'Subdomains', 'Open Ports', 'Vulnerabilities']
            st.dataframe(df_sorted[display_columns], use_container_width=True)
            
            # Add row selection via selectbox
            if len(df_sorted) > 0:
                selected_idx = st.selectbox(
                    "Select a report to view details:",
                    range(len(df_sorted)),
                    format_func=lambda x: f"{df_sorted.iloc[x]['Target']} - {df_sorted.iloc[x]['Scan Date']}"
                )
                st.session_state.selected_report_idx = df_sorted.iloc[selected_idx]['Index']
            else:
                st.session_state.selected_report_idx = None
                
        except Exception as table_error:
            st.error(f"❌ Error displaying table: {str(table_error)}")
            logger.error(f"Table display error: {str(table_error)}")
            # Fallback to simple display
            if table_data:
                st.write("**Reports Summary:**")
                for i, data in enumerate(table_data):
                    if st.button(f"{data.get('Target', 'Unknown')} - {data.get('Scan Date', 'Unknown')}", key=f"report_{i}"):
                        st.session_state.selected_report_idx = data.get('Index', i)
                        st.rerun()
            st.session_state.selected_report_idx = None
        
        # Handle pagination for large datasets
        if len(table_data) > 50:
            st.info(f"📊 Showing all {len(table_data)} reports. Consider using filters to narrow down results for better performance.")
        elif len(table_data) > 100:
            st.warning(f"⚠️ Large dataset ({len(table_data)} reports) may impact performance. Consider using filters.")
        
        # Store selected row information in session state for expansion functionality
        try:
            if selected_rows and hasattr(selected_rows, 'selection') and selected_rows.selection.rows:
                selected_idx = selected_rows.selection.rows[0]
                # Get the original report index from the sorted dataframe
                original_idx = df_sorted.iloc[selected_idx]['Index']
                st.session_state.selected_report_idx = original_idx
            elif 'selected_report_idx' not in st.session_state:
                st.session_state.selected_report_idx = None
        except Exception as selection_error:
            st.warning(f"⚠️ Row selection error: {str(selection_error)}")
            st.session_state.selected_report_idx = None
        
        # Show expandable row details if a row is selected
        try:
            if st.session_state.selected_report_idx is not None:
                if st.session_state.selected_report_idx < len(reports):
                    render_report_details(reports[st.session_state.selected_report_idx])
                else:
                    st.error("❌ Selected report index is out of range")
                    st.session_state.selected_report_idx = None
            else:
                st.caption("💡 Click on a row above to view detailed report information")
        except Exception as details_error:
            st.error(f"❌ Error displaying report details: {str(details_error)}")
        
    except Exception as e:
        st.error("❌ Critical error rendering reports table")
        st.error(f"Error details: {str(e)}")
        
        # Provide recovery suggestions
        st.markdown("""
        ### 🔧 Troubleshooting Steps:
        1. **Refresh the data:** Click '🔄 Refresh Data' in the sidebar
        2. **Check report files:** Ensure JSON files in reports/ directory are valid
        3. **Clear filters:** Try resetting all filters
        4. **Restart application:** If issues persist, restart the Streamlit app
        """)
        
        # Show technical details in expander for debugging
        with st.expander("🔍 Technical Details", expanded=False):
            st.exception(e)

def render_ai_summary_section(report: Dict, data_issues: List[str]):
    """Render AI summary section with enhanced error handling and display"""
    target = report.get('target', 'Unknown')
    report_hash = hash(str(sorted(report.items())))
    
    # Initialize loading state for this report
    loading_key = f"ai_loading_{target}_{report_hash}"
    if loading_key not in st.session_state.ai_loading_states:
        st.session_state.ai_loading_states[loading_key] = False
    
    # Check if AI is enabled
    if not st.session_state.ai_analyzer.is_enabled():
        with st.expander("🤖 AI Analysis Summary", expanded=False):
            st.warning("⚠️ AI functionality disabled - configure OPENROUTER_API_KEY to enable")
            st.markdown("""
            **To enable AI summaries:**
            1. Set the `OPENROUTER_API_KEY` environment variable with your OpenRouter API key
            2. Restart the application
            3. AI summaries will then be available for all reports
            
            **Get an API key:**
            - Visit [OpenRouter.ai](https://openrouter.ai) to create an account
            - Generate an API key in your account settings
            - Set it as an environment variable: `OPENROUTER_API_KEY=your_key_here`
            """)
        return
    
    # Check for existing AI summary
    ai_summary = report.get('ai_summary')
    has_cached_summary = ai_summary and isinstance(ai_summary, str) and ai_summary.strip()
    
    # Check if this summary is from cache
    cached_summary = st.session_state.ai_analyzer.get_cached_summary(report)
    is_from_cache = cached_summary is not None
    
    # Create AI summary section
    with st.expander("🤖 AI Analysis Summary", expanded=has_cached_summary):
        # Show loading state if currently generating
        if st.session_state.ai_loading_states.get(loading_key, False):
            st.info("🤖 Generating AI analysis... This may take 10-30 seconds.")
            st.progress(0.5)  # Indeterminate progress
        
        # AI summary controls
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            if has_cached_summary:
                cache_indicator = "💾" if is_from_cache else "🆕"
                st.success(f"✅ AI summary available {cache_indicator}")
                if is_from_cache:
                    st.caption("💾 Loaded from cache (no API call needed)")
            else:
                st.info("💡 Generate AI threat assessment for this report")
        
        with col2:
            # Generate/Regenerate AI summary button
            button_text = "🔄 Regenerate" if has_cached_summary else "🤖 Generate Summary"
            button_key = f"ai_generate_{target}_{report_hash}"
            button_disabled = st.session_state.ai_loading_states.get(loading_key, False)
            
            if st.button(button_text, key=button_key, disabled=button_disabled, 
                        help="Generate AI threat analysis using OpenRouter API"):
                # Set loading state
                st.session_state.ai_loading_states[loading_key] = True
                
                # Create placeholder for status updates
                status_placeholder = st.empty()
                progress_placeholder = st.empty()
                
                try:
                    # Show detailed progress
                    status_placeholder.info("🔄 Preparing request...")
                    progress_placeholder.progress(0.1)
                    
                    # Validate API key first
                    if not st.session_state.ai_analyzer.validate_api_key():
                        status_placeholder.error("❌ Invalid API key. Please check your OPENROUTER_API_KEY.")
                        st.session_state.ai_loading_states[loading_key] = False
                        return
                    
                    status_placeholder.info("🤖 Sending request to AI service...")
                    progress_placeholder.progress(0.3)
                    
                    # Generate AI summary with enhanced error handling
                    new_summary = st.session_state.ai_analyzer.generate_summary(report)
                    
                    progress_placeholder.progress(0.8)
                    
                    if new_summary and isinstance(new_summary, str) and new_summary.strip():
                        # Update the report with new summary
                        report['ai_summary'] = new_summary
                        status_placeholder.success("✅ AI summary generated successfully!")
                        progress_placeholder.progress(1.0)
                        
                        # Clear loading state and refresh
                        st.session_state.ai_loading_states[loading_key] = False
                        st.rerun()
                    else:
                        status_placeholder.error("❌ AI service returned empty response. Please try again.")
                        
                except requests.exceptions.Timeout:
                    status_placeholder.error("⏱️ Request timed out. The AI service may be busy. Please try again.")
                except requests.exceptions.ConnectionError:
                    status_placeholder.error("🌐 Connection failed. Please check your internet connection.")
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code == 401:
                        status_placeholder.error("🔑 Authentication failed. Please check your API key.")
                    elif e.response.status_code == 429:
                        status_placeholder.error("⏳ Rate limit exceeded. Please wait a moment and try again.")
                    elif e.response.status_code == 402:
                        status_placeholder.error("💳 Insufficient credits. Please check your OpenRouter account balance.")
                    else:
                        status_placeholder.error(f"🚫 API error ({e.response.status_code}). Please try again later.")
                except Exception as e:
                    status_placeholder.error(f"❌ Unexpected error: {str(e)}")
                    # Show detailed error for debugging
                    with st.expander("🔍 Error Details", expanded=False):
                        st.exception(e)
                
                finally:
                    # Always clear loading state
                    st.session_state.ai_loading_states[loading_key] = False
                    progress_placeholder.empty()
        
        with col3:
            # Clear AI summary button (only show if summary exists)
            if has_cached_summary:
                clear_key = f"ai_clear_{target}_{report_hash}"
                if st.button("🗑️ Clear", key=clear_key, help="Remove AI summary"):
                    report['ai_summary'] = None
                    # Also clear from analyzer cache
                    try:
                        st.session_state.ai_analyzer.cache.pop(
                            st.session_state.ai_analyzer._generate_cache_key(report), None
                        )
                    except:
                        pass
                    st.success("✅ AI summary cleared")
                    st.rerun()
        
        # Display AI summary with enhanced formatting
        if has_cached_summary:
            render_ai_summary_display(ai_summary, is_from_cache)
        
        # Show retry options and help for failed attempts
        elif not has_cached_summary and not st.session_state.ai_loading_states.get(loading_key, False):
            render_ai_summary_help()
    
    # Validate AI summary format if present
    if ai_summary is not None and not isinstance(ai_summary, str):
        data_issues.append("AI Summary: Invalid format (expected string)")


def render_ai_summary_display(ai_summary: str, is_from_cache: bool):
    """Render the AI summary with enhanced formatting and structure"""
    try:
        st.markdown("### 🎯 AI Threat Assessment")
        
        # Parse and format the AI summary for better readability
        lines = ai_summary.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Detect section headers
            if any(keyword in line.upper() for keyword in ['RISK LEVEL', 'KEY CONCERNS', 'ATTACK VECTORS', 'RECOMMENDATIONS']):
                if 'RISK LEVEL' in line.upper():
                    st.markdown("#### 🚨 Risk Assessment")
                elif 'KEY CONCERNS' in line.upper():
                    st.markdown("#### ⚠️ Key Security Concerns")
                elif 'ATTACK VECTORS' in line.upper():
                    st.markdown("#### 🔍 Potential Attack Vectors")
                elif 'RECOMMENDATIONS' in line.upper():
                    st.markdown("#### 💡 Security Recommendations")
                current_section = line
            else:
                # Format content based on context
                if line.startswith('-') or line.startswith('•'):
                    st.markdown(f"- {line[1:].strip()}")
                elif line.startswith(('1.', '2.', '3.', '4.', '5.')):
                    st.markdown(f"**{line}**")
                else:
                    st.markdown(line)
        
        # Add metadata
        st.markdown("---")
        col1, col2 = st.columns(2)
        with col1:
            if is_from_cache:
                st.caption("💾 Cached result - no API usage")
            else:
                st.caption("🆕 Fresh analysis from AI service")
        
        with col2:
            st.caption("🤖 Powered by OpenRouter AI")
            
    except Exception as e:
        # Fallback to simple display
        st.markdown("### 🎯 AI Threat Assessment")
        st.markdown(ai_summary)
        st.caption(f"⚠️ Display formatting error: {str(e)}")


def render_ai_batch_section():
    """Render batch AI summary generation section"""
    st.subheader("🤖 AI-Powered Analysis")
    
    reports = st.session_state.filtered_reports
    
    if not st.session_state.ai_analyzer.is_enabled():
        st.warning("⚠️ AI functionality disabled - configure OPENROUTER_API_KEY environment variable to enable")
        with st.expander("ℹ️ How to Enable AI Features", expanded=False):
            st.markdown("""
            **Steps to enable AI analysis:**
            1. **Get an API key** from [OpenRouter.ai](https://openrouter.ai)
            2. **Set environment variable**: `OPENROUTER_API_KEY=your_key_here`
            3. **Restart the application**
            4. **Generate summaries** for individual reports or in batch
            
            **AI Features:**
            - Individual report threat assessments
            - Batch processing for multiple reports
            - Intelligent caching to minimize API usage
            - Detailed risk analysis and recommendations
            """)
        return
    
    if not reports:
        st.info("📁 No reports available for AI analysis. Add reports to get started.")
        return
    
    # Show AI analysis overview
    col1, col2, col3 = st.columns(3)
    
    # Count reports with/without AI summaries
    reports_with_ai = sum(1 for r in reports if r.get('ai_summary'))
    reports_without_ai = len(reports) - reports_with_ai
    
    with col1:
        st.metric("📊 Total Reports", len(reports))
    
    with col2:
        st.metric("✅ With AI Analysis", reports_with_ai)
    
    with col3:
        st.metric("⏳ Pending Analysis", reports_without_ai)
    
    # Batch AI generation controls
    if reports_without_ai > 0:
        st.markdown("### 🚀 Batch AI Analysis")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.info(f"💡 Generate AI summaries for {reports_without_ai} reports without analysis")
        
        with col2:
            if st.button("🤖 Generate All", help=f"Generate AI summaries for {reports_without_ai} reports"):
                render_batch_ai_generation(reports)
    
    # Show recent AI analysis results
    if reports_with_ai > 0:
        st.markdown("### 📋 Recent AI Analysis")
        
        # Show summary of AI-analyzed reports
        ai_reports = [r for r in reports if r.get('ai_summary')][:5]  # Show last 5
        
        for report in ai_reports:
            target = report.get('target', 'Unknown')
            scan_date = report.get('scan_date', 'Unknown')
            
            with st.expander(f"🎯 {target} - {scan_date}", expanded=False):
                ai_summary = report.get('ai_summary', '')
                
                # Extract risk level if present
                risk_level = "Unknown"
                if 'CRITICAL' in ai_summary.upper():
                    risk_level = "🔴 Critical"
                elif 'HIGH' in ai_summary.upper():
                    risk_level = "🟠 High"
                elif 'MEDIUM' in ai_summary.upper():
                    risk_level = "🟡 Medium"
                elif 'LOW' in ai_summary.upper():
                    risk_level = "🟢 Low"
                
                col1, col2 = st.columns([1, 3])
                with col1:
                    st.markdown(f"**Risk Level:** {risk_level}")
                
                with col2:
                    # Show first few lines of summary
                    summary_preview = ai_summary[:200] + "..." if len(ai_summary) > 200 else ai_summary
                    st.markdown(f"**Preview:** {summary_preview}")


def render_batch_ai_generation(reports: List[Dict]):
    """Handle batch AI summary generation with progress tracking"""
    reports_to_process = [r for r in reports if not r.get('ai_summary')]
    
    if not reports_to_process:
        st.success("✅ All reports already have AI summaries!")
        return
    
    # Create progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    results_container = st.container()
    
    successful = 0
    failed = 0
    
    try:
        for i, report in enumerate(reports_to_process):
            target = report.get('target', f'Report {i+1}')
            
            # Update progress
            progress = (i + 1) / len(reports_to_process)
            progress_bar.progress(progress)
            status_text.text(f"Processing {target} ({i+1}/{len(reports_to_process)})")
            
            try:
                # Generate AI summary
                summary = st.session_state.ai_analyzer.generate_summary(report)
                
                if summary:
                    report['ai_summary'] = summary
                    successful += 1
                    
                    with results_container:
                        st.success(f"✅ {target} - Analysis completed")
                else:
                    failed += 1
                    with results_container:
                        st.error(f"❌ {target} - Analysis failed")
                
                # Small delay to avoid overwhelming the API
                import time
                time.sleep(1)
                
            except Exception as e:
                failed += 1
                with results_container:
                    st.error(f"❌ {target} - Error: {str(e)}")
    
    except Exception as e:
        st.error(f"❌ Batch processing error: {str(e)}")
    
    finally:
        # Show final results
        progress_bar.progress(1.0)
        status_text.text("Batch processing completed!")
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("✅ Successful", successful)
        with col2:
            st.metric("❌ Failed", failed)
        
        if successful > 0:
            st.success(f"🎉 Successfully generated {successful} AI summaries!")
            st.balloons()


def render_ai_summary_help():
    """Render help information for AI summary generation"""
    st.markdown("""
    **🤖 AI Analysis Features:**
    - 🎯 **Risk Level Assessment** - Categorizes threat level (Low/Medium/High/Critical)
    - ⚠️ **Key Security Concerns** - Identifies top priority issues
    - 🔍 **Attack Vector Analysis** - Explains potential exploitation methods  
    - 💡 **Actionable Recommendations** - Provides specific security improvements
    
    **💡 Tips:**
    - Analysis typically takes 10-30 seconds
    - Results are cached to avoid duplicate API calls
    - Requires active internet connection and valid API key
    - More detailed reports generate more comprehensive analysis
    """)
    
    # Show API status
    try:
        if st.session_state.ai_analyzer.validate_api_key():
            st.success("✅ API connection verified")
        else:
            st.warning("⚠️ API key validation failed")
    except:
        st.info("🔄 API status check unavailable")


def render_report_details(report: Dict):
    """Render detailed view of a selected report with expandable sections"""
    if not report:
        st.warning("⚠️ No report data available to display")
        return
    
    if not isinstance(report, dict):
        st.error("❌ Invalid report format - expected dictionary structure")
        return
    
    try:
        st.markdown("---")
        st.subheader("🔍 Report Details")
        
        # Basic report information with error handling
        col1, col2 = st.columns(2)
        
        with col1:
            target = report.get('target', 'Unknown')
            scan_date = report.get('scan_date', 'Unknown')
            
            # Validate and display target
            if not isinstance(target, str):
                target = str(target) if target is not None else 'Unknown'
            st.markdown(f"**🎯 Target:** {target}")
            
            # Validate and display scan date
            if not isinstance(scan_date, str):
                scan_date = str(scan_date) if scan_date is not None else 'Unknown'
            st.markdown(f"**📅 Scan Date:** {scan_date}")
        
        with col2:
            # Add collapse button
            if st.button("❌ Close Details", key="close_details"):
                st.session_state.selected_report_idx = None
                st.rerun()
        
        # Track any data issues for user feedback
        data_issues = []
        
        # Subdomains Section with robust error handling
        try:
            subdomains = report.get('subdomains', [])
            if subdomains and isinstance(subdomains, list):
                # Filter out invalid subdomain entries
                valid_subdomains = [s for s in subdomains if isinstance(s, str) and s.strip()]
                invalid_count = len(subdomains) - len(valid_subdomains)
                
                if invalid_count > 0:
                    data_issues.append(f"Subdomains: {invalid_count} invalid entries filtered out")
                
                if valid_subdomains:
                    with st.expander(f"🌐 Subdomains ({len(valid_subdomains)})", expanded=True):
                        if len(valid_subdomains) <= 20:
                            # Show all subdomains if not too many
                            try:
                                for subdomain in sorted(valid_subdomains):
                                    st.write(f"• {subdomain}")
                            except Exception as sort_error:
                                # Fallback to unsorted display
                                for subdomain in valid_subdomains:
                                    st.write(f"• {subdomain}")
                        else:
                            # Show first 20 and provide option to see all
                            try:
                                sorted_subdomains = sorted(valid_subdomains)
                                for subdomain in sorted_subdomains[:20]:
                                    st.write(f"• {subdomain}")
                                
                                if st.button(f"Show all {len(valid_subdomains)} subdomains", key="show_all_subdomains"):
                                    st.write("**All subdomains:**")
                                    for subdomain in sorted_subdomains:
                                        st.write(f"• {subdomain}")
                            except Exception as display_error:
                                st.warning(f"⚠️ Error displaying subdomains: {str(display_error)}")
                                # Show raw list as fallback
                                st.write(valid_subdomains)
                else:
                    st.info("🌐 No valid subdomains found in this report")
            elif subdomains is not None and not isinstance(subdomains, list):
                data_issues.append("Subdomains: Invalid format (expected list)")
                st.warning("⚠️ Subdomains data is in invalid format")
            else:
                st.info("🌐 No subdomains found in this report")
        except Exception as subdomain_error:
            st.error(f"❌ Error processing subdomains: {str(subdomain_error)}")
        
        # Open Ports Section with robust error handling
        try:
            open_ports = report.get('open_ports', {})
            if open_ports and isinstance(open_ports, dict):
                # Filter out invalid port entries
                valid_ports = {}
                for port, service in open_ports.items():
                    if isinstance(port, (str, int)):
                        service_str = str(service) if service is not None else 'Unknown'
                        valid_ports[str(port)] = service_str
                
                invalid_count = len(open_ports) - len(valid_ports)
                if invalid_count > 0:
                    data_issues.append(f"Open Ports: {invalid_count} invalid entries filtered out")
                
                if valid_ports:
                    with st.expander(f"🔌 Open Ports ({len(valid_ports)})", expanded=True):
                        try:
                            # Create a nice table for ports and services
                            port_data = []
                            for port, service in valid_ports.items():
                                port_data.append({
                                    'Port': port,
                                    'Service': service if service else 'Unknown'
                                })
                            
                            if port_data:
                                port_df = pd.DataFrame(port_data)
                                # Sort by port number (convert to int for proper sorting)
                                try:
                                    port_df['Port_Int'] = pd.to_numeric(port_df['Port'], errors='coerce')
                                    port_df = port_df.sort_values('Port_Int').drop('Port_Int', axis=1)
                                except:
                                    # If conversion fails, sort as strings
                                    port_df = port_df.sort_values('Port')
                                
                                st.dataframe(port_df, use_container_width=True, hide_index=True)
                        except Exception as port_display_error:
                            st.warning(f"⚠️ Error displaying ports table: {str(port_display_error)}")
                            # Fallback to simple list
                            for port, service in valid_ports.items():
                                st.write(f"• Port {port}: {service}")
                else:
                    st.info("🔌 No valid open ports found in this report")
            elif open_ports is not None and not isinstance(open_ports, dict):
                data_issues.append("Open Ports: Invalid format (expected dictionary)")
                st.warning("⚠️ Open ports data is in invalid format")
            else:
                st.info("🔌 No open ports found in this report")
        except Exception as ports_error:
            st.error(f"❌ Error processing open ports: {str(ports_error)}")
        
        # Vulnerabilities Section with robust error handling
        try:
            vulnerabilities = report.get('vulnerabilities', [])
            if vulnerabilities and isinstance(vulnerabilities, list):
                # Filter out invalid vulnerability entries
                valid_vulns = [v for v in vulnerabilities if isinstance(v, dict)]
                invalid_count = len(vulnerabilities) - len(valid_vulns)
                
                if invalid_count > 0:
                    data_issues.append(f"Vulnerabilities: {invalid_count} invalid entries filtered out")
                
                if valid_vulns:
                    with st.expander(f"🚨 Vulnerabilities ({len(valid_vulns)})", expanded=True):
                        for i, vuln in enumerate(valid_vulns):
                            try:
                                # Create a card-like display for each vulnerability
                                severity = str(vuln.get('severity', 'unknown')).lower()
                                
                                # Color code by severity
                                severity_colors = {
                                    'critical': '🔴',
                                    'high': '🟠', 
                                    'medium': '🟡',
                                    'low': '🟢',
                                    'unknown': '⚪'
                                }
                                
                                severity_icon = severity_colors.get(severity, '⚪')
                                
                                # Safely extract vulnerability fields
                                title = str(vuln.get('title', 'Unknown'))
                                affected_service = str(vuln.get('affected_service', 'Unknown'))
                                description = str(vuln.get('description', 'No description available'))
                                
                                st.markdown(f"""
                                **{severity_icon} Vulnerability {i+1}**
                                - **Title:** {title}
                                - **Severity:** {severity.title()}
                                - **Affected Service:** {affected_service}
                                - **Description:** {description}
                                """)
                                
                                # Show CVE ID if available
                                cve_id = vuln.get('cve_id')
                                if cve_id:
                                    st.markdown(f"- **CVE ID:** {str(cve_id)}")
                                
                                # Add separator between vulnerabilities
                                if i < len(valid_vulns) - 1:
                                    st.markdown("---")
                                    
                            except Exception as vuln_error:
                                st.warning(f"⚠️ Error displaying vulnerability {i+1}: {str(vuln_error)}")
                else:
                    st.info("🚨 No valid vulnerabilities found in this report")
            elif vulnerabilities is not None and not isinstance(vulnerabilities, list):
                data_issues.append("Vulnerabilities: Invalid format (expected list)")
                st.warning("⚠️ Vulnerabilities data is in invalid format")
            else:
                st.info("🚨 No vulnerabilities found in this report")
        except Exception as vulns_error:
            st.error(f"❌ Error processing vulnerabilities: {str(vulns_error)}")
        
        # AI Summary Section with controls and error handling
        try:
            render_ai_summary_section(report, data_issues)
        except Exception as ai_error:
            st.warning(f"⚠️ Error in AI summary section: {str(ai_error)}")
        
        # Show data issues summary if any
        if data_issues:
            with st.expander(f"⚠️ Data Quality Issues ({len(data_issues)})", expanded=False):
                for issue in data_issues:
                    st.warning(issue)
                st.info("These issues don't prevent viewing the report, but may indicate problems with the source data.")
        
        # Raw Data Section (collapsible) with error handling
        try:
            with st.expander("📄 Raw Report Data", expanded=False):
                st.json(report)
        except Exception as json_error:
            with st.expander("📄 Raw Report Data", expanded=False):
                st.warning(f"⚠️ Error displaying JSON: {str(json_error)}")
                st.text(str(report))
        
    except Exception as e:
        st.error("❌ Critical error rendering report details")
        st.error(f"Error details: {str(e)}")
        
        # Provide recovery options
        st.markdown("""
        ### 🔧 Recovery Options:
        1. **Close and reselect:** Close this detail view and select the report again
        2. **Check data format:** The report may have invalid data structure
        3. **View raw data:** Try viewing the raw report data below
        """)
        
        # Try to show raw data as fallback
        try:
            with st.expander("🔍 Raw Report Data (Fallback)", expanded=True):
                st.write(report)
        except:
            st.error("❌ Cannot display raw report data")
        
        # Show technical details for debugging
        with st.expander("🔍 Technical Details", expanded=False):
            st.exception(e)

def render_main_content():
    """Render the main content area with placeholder sections"""
    
    # Show loading status if no reports
    if not st.session_state.reports:
        st.warning("⚠️ No reports loaded. Click 'Force Reload' to try loading reports again.")
        col1, col2, col3 = st.columns(3)
        with col2:
            if st.button("🔄 Force Reload Reports", key="main_reload"):
                st.session_state.force_reload = True
                st.rerun()
    
    # KPI Cards Section
    render_kpi_cards()
    
    st.markdown("---")
    
    # Charts Section
    st.subheader("📈 Data Visualizations")
    chart_col1, chart_col2, chart_col3 = st.columns(3)
    
    with chart_col1:
        st.subheader("📊 Subdomain Distribution")
        render_subdomain_chart()
    
    with chart_col2:
        st.subheader("🥧 Open Ports Distribution")
        render_ports_chart()
    
    with chart_col3:
        st.subheader("📅 Timeline Activity")
        render_timeline_chart()
    
    st.markdown("---")
    
    # Data Table Section
    render_reports_table()
    
    st.markdown("---")
    
    # AI Summary Section
    render_ai_batch_section()

def check_system_status():
    """Check system status and dependencies"""
    status = {
        'reports_dir_exists': os.path.exists('reports'),
        'json_files_found': [],
        'reports_loaded': 0,
        'ai_enabled': False,
        'errors': []
    }
    
    try:
        if status['reports_dir_exists']:
            status['json_files_found'] = [f for f in os.listdir('reports') if f.lower().endswith('.json')]
        
        status['reports_loaded'] = len(st.session_state.get('reports', []))
        status['ai_enabled'] = st.session_state.get('ai_analyzer', AIAnalyzer()).is_enabled()
        
    except Exception as e:
        status['errors'].append(str(e))
    
    return status

def main():
    """Main application function"""
    try:
        # Initialize session state
        initialize_session_state()
        
        # Load reports on first run or force reload
        if not st.session_state.reports or st.session_state.get('force_reload', False):
            st.session_state.reports = load_reports()
            st.session_state.filtered_reports = st.session_state.reports
            st.session_state.force_reload = False
        
        # Render UI components
        render_header()
        render_sidebar()
        render_main_content()
        
        # Footer with status
        st.markdown("---")
        status = check_system_status()
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("*AI Threat Hunting Dashboard - Local cybersecurity analytics tool*")
        with col2:
            st.caption(f"Status: {status['reports_loaded']} reports loaded | AI: {'✅' if status['ai_enabled'] else '❌'}")
            
    except Exception as e:
        st.error(f"Critical application error: {str(e)}")
        logger.error(f"Main application error: {str(e)}")
        st.info("Please refresh the page or check the logs for more details.")

if __name__ == "__main__":
    main()