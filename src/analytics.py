"""
Analytics and data processing module for AI Threat Hunting Dashboard.

This module provides functionality to calculate KPIs, generate statistics,
filter reports, and prepare data for visualization components.
"""

import logging
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime, date
from collections import Counter, defaultdict


class ReportAnalytics:
    """
    Handles analytics and data processing for reconnaissance reports.
    
    This class provides methods to calculate KPIs, filter reports,
    and generate data structures for visualization components.
    """
    
    def __init__(self):
        """Initialize the ReportAnalytics."""
        self.logger = logging.getLogger(__name__)
    
    def calculate_kpis(self, reports: List[Dict]) -> Dict[str, Any]:
        """
        Calculate key performance indicators from the reports.
        
        Args:
            reports: List of report dictionaries
            
        Returns:
            Dictionary containing KPI metrics:
            - total_reports: Total number of reports
            - total_subdomains: Total unique subdomains across all reports
            - avg_open_ports: Average number of open ports per target
            - total_vulnerabilities: Total number of vulnerabilities found
        """
        if not reports:
            return {
                'total_reports': 0,
                'total_subdomains': 0,
                'avg_open_ports': 0.0,
                'total_vulnerabilities': 0
            }
        
        try:
            # Total number of reports
            total_reports = len(reports)
            
            # Collect all unique subdomains
            all_subdomains = set()
            total_ports = 0
            total_vulnerabilities = 0
            
            for report in reports:
                # Skip None reports
                if report is None or not isinstance(report, dict):
                    continue
                    
                # Add subdomains to the set (automatically handles uniqueness)
                if 'subdomains' in report and isinstance(report['subdomains'], list):
                    all_subdomains.update(report['subdomains'])
                
                # Count open ports
                if 'open_ports' in report and isinstance(report['open_ports'], dict):
                    total_ports += len(report['open_ports'])
                
                # Count vulnerabilities
                if 'vulnerabilities' in report and isinstance(report['vulnerabilities'], list):
                    total_vulnerabilities += len(report['vulnerabilities'])
            
            # Calculate average open ports per target
            avg_open_ports = total_ports / total_reports if total_reports > 0 else 0.0
            
            kpis = {
                'total_reports': total_reports,
                'total_subdomains': len(all_subdomains),
                'avg_open_ports': round(avg_open_ports, 1),
                'total_vulnerabilities': total_vulnerabilities
            }
            
            self.logger.debug(f"Calculated KPIs: {kpis}")
            return kpis
            
        except Exception as e:
            self.logger.error(f"Error calculating KPIs: {str(e)}")
            return {
                'total_reports': 0,
                'total_subdomains': 0,
                'avg_open_ports': 0.0,
                'total_vulnerabilities': 0
            }
    
    def get_subdomain_counts(self, reports: List[Dict]) -> Dict[str, int]:
        """
        Get subdomain counts per target for visualization.
        
        Args:
            reports: List of report dictionaries
            
        Returns:
            Dictionary mapping target names to subdomain counts
        """
        subdomain_counts = {}
        
        try:
            for report in reports:
                target = report.get('target', 'Unknown')
                subdomains = report.get('subdomains', [])
                
                if isinstance(subdomains, list):
                    subdomain_counts[target] = len(subdomains)
                else:
                    subdomain_counts[target] = 0
                    
        except Exception as e:
            self.logger.error(f"Error calculating subdomain counts: {str(e)}")
            
        return subdomain_counts
    
    def get_port_distribution(self, reports: List[Dict]) -> Dict[str, int]:
        """
        Get distribution of open ports across all reports.
        
        Args:
            reports: List of report dictionaries
            
        Returns:
            Dictionary mapping port numbers to occurrence counts
        """
        port_counter = Counter()
        
        try:
            for report in reports:
                open_ports = report.get('open_ports', {})
                
                if isinstance(open_ports, dict):
                    # Count each port occurrence
                    for port in open_ports.keys():
                        port_counter[port] += 1
                        
        except Exception as e:
            self.logger.error(f"Error calculating port distribution: {str(e)}")
            
        return dict(port_counter)
    
    def get_timeline_data(self, reports: List[Dict]) -> List[Tuple[str, int]]:
        """
        Get timeline data showing report activity over time.
        
        Args:
            reports: List of report dictionaries
            
        Returns:
            List of tuples containing (date_string, report_count)
        """
        date_counter = Counter()
        
        try:
            for report in reports:
                scan_date = report.get('scan_date', '')
                
                if scan_date:
                    # Parse and normalize the date
                    try:
                        # Try to parse the date string
                        if isinstance(scan_date, str):
                            # Handle various date formats
                            parsed_date = self._parse_date(scan_date)
                            if parsed_date:
                                date_str = parsed_date.strftime('%Y-%m-%d')
                                date_counter[date_str] += 1
                    except Exception as date_error:
                        self.logger.warning(f"Could not parse date '{scan_date}': {str(date_error)}")
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error generating timeline data: {str(e)}")
            
        # Sort by date and return as list of tuples
        sorted_dates = sorted(date_counter.items())
        return sorted_dates    

    def filter_reports(self, reports: List[Dict], filters: Dict[str, Any]) -> List[Dict]:
        """
        Filter reports based on provided criteria.
        
        Args:
            reports: List of report dictionaries to filter
            filters: Dictionary containing filter criteria:
                - selected_targets: List of target names to include
                - date_range: Tuple of (start_date, end_date) as datetime objects
                - keyword_search: String to search for in targets, subdomains, and vulnerabilities
                - show_ai_summaries: Boolean to filter reports with/without AI summaries
                
        Returns:
            List of filtered report dictionaries
        """
        if not reports:
            return []
            
        filtered_reports = reports.copy()
        
        try:
            # Filter by selected targets
            selected_targets = filters.get('selected_targets', [])
            if selected_targets:
                filtered_reports = [
                    report for report in filtered_reports
                    if report.get('target', '') in selected_targets
                ]
                self.logger.debug(f"After target filter: {len(filtered_reports)} reports")
            
            # Filter by date range
            date_range = filters.get('date_range')
            if date_range and len(date_range) == 2:
                start_date, end_date = date_range
                if start_date and end_date:
                    filtered_reports = self._filter_by_date_range(
                        filtered_reports, start_date, end_date
                    )
                    self.logger.debug(f"After date filter: {len(filtered_reports)} reports")
            
            # Filter by keyword search
            keyword_search = filters.get('keyword_search', '').strip()
            if keyword_search:
                filtered_reports = self._filter_by_keyword(filtered_reports, keyword_search)
                self.logger.debug(f"After keyword filter: {len(filtered_reports)} reports")
            
            # Filter by AI summary presence
            show_ai_summaries = filters.get('show_ai_summaries')
            if show_ai_summaries is not None:
                if show_ai_summaries:
                    # Show only reports with AI summaries
                    filtered_reports = [
                        report for report in filtered_reports
                        if report.get('ai_summary') is not None and report.get('ai_summary', '').strip()
                    ]
                else:
                    # Show only reports without AI summaries
                    filtered_reports = [
                        report for report in filtered_reports
                        if report.get('ai_summary') is None or not report.get('ai_summary', '').strip()
                    ]
                self.logger.debug(f"After AI summary filter: {len(filtered_reports)} reports")
            
            self.logger.info(f"Filtered {len(reports)} reports down to {len(filtered_reports)}")
            return filtered_reports
            
        except Exception as e:
            self.logger.error(f"Error filtering reports: {str(e)}")
            return reports  # Return original reports if filtering fails
    
    def generate_chart_data(self, reports: List[Dict]) -> Dict[str, Any]:
        """
        Generate data structures for all chart visualizations.
        
        Args:
            reports: List of report dictionaries
            
        Returns:
            Dictionary containing data for all charts:
            - subdomain_counts: Data for subdomain bar chart
            - port_distribution: Data for port pie chart
            - timeline_data: Data for timeline chart
        """
        try:
            chart_data = {
                'subdomain_counts': self.get_subdomain_counts(reports),
                'port_distribution': self.get_port_distribution(reports),
                'timeline_data': self.get_timeline_data(reports)
            }
            
            self.logger.debug("Generated chart data for all visualizations")
            return chart_data
            
        except Exception as e:
            self.logger.error(f"Error generating chart data: {str(e)}")
            return {
                'subdomain_counts': {},
                'port_distribution': {},
                'timeline_data': []
            }
    
    def get_unique_targets(self, reports: List[Dict]) -> List[str]:
        """
        Get list of unique target names from reports.
        
        Args:
            reports: List of report dictionaries
            
        Returns:
            Sorted list of unique target names
        """
        targets = set()
        
        try:
            for report in reports:
                target = report.get('target', '')
                if target and isinstance(target, str):
                    targets.add(target.strip())
                    
        except Exception as e:
            self.logger.error(f"Error extracting unique targets: {str(e)}")
            
        return sorted(list(targets))
    
    def get_date_range(self, reports: List[Dict]) -> Tuple[Optional[datetime], Optional[datetime]]:
        """
        Get the date range (min and max dates) from all reports.
        
        Args:
            reports: List of report dictionaries
            
        Returns:
            Tuple of (earliest_date, latest_date) or (None, None) if no valid dates
        """
        dates = []
        
        try:
            for report in reports:
                scan_date_str = report.get('scan_date', '')
                if scan_date_str:
                    parsed_date = self._parse_date(scan_date_str)
                    if parsed_date:
                        dates.append(parsed_date)
                        
        except Exception as e:
            self.logger.error(f"Error calculating date range: {str(e)}")
            
        if not dates:
            return None, None
            
        return min(dates), max(dates)
    
    def _parse_date(self, date_string: str) -> Optional[datetime]:
        """
        Parse a date string into a datetime object.
        
        Args:
            date_string: Date string to parse
            
        Returns:
            Parsed datetime object or None if parsing fails
        """
        # Common date formats to try
        date_formats = [
            '%Y-%m-%d',
            '%Y/%m/%d',
            '%d-%m-%Y',
            '%d/%m/%Y',
            '%Y-%m-%d %H:%M:%S',
            '%Y/%m/%d %H:%M:%S'
        ]
        
        for fmt in date_formats:
            try:
                return datetime.strptime(date_string.strip(), fmt)
            except ValueError:
                continue
                
        return None
    
    def _filter_by_date_range(self, reports: List[Dict], start_date: datetime, end_date: datetime) -> List[Dict]:
        """
        Filter reports by date range.
        
        Args:
            reports: List of reports to filter
            start_date: Start date for filtering
            end_date: End date for filtering
            
        Returns:
            List of reports within the date range
        """
        filtered_reports = []
        
        for report in reports:
            scan_date_str = report.get('scan_date', '')
            if not scan_date_str:
                continue
                
            try:
                scan_date = self._parse_date(scan_date_str)
                if scan_date:
                    # Convert to date for comparison (ignore time)
                    scan_date_only = scan_date.date()
                    start_date_only = start_date.date() if hasattr(start_date, 'date') else start_date
                    end_date_only = end_date.date() if hasattr(end_date, 'date') else end_date
                    
                    if start_date_only <= scan_date_only <= end_date_only:
                        filtered_reports.append(report)
            except Exception as e:
                self.logger.warning(f"Error parsing date for filtering: {str(e)}")
                continue
                
        return filtered_reports
    
    def _filter_by_keyword(self, reports: List[Dict], keyword: str) -> List[Dict]:
        """
        Filter reports by keyword search in targets, subdomains, and vulnerability descriptions.
        
        Args:
            reports: List of reports to filter
            keyword: Keyword to search for (case-insensitive)
            
        Returns:
            List of reports matching the keyword
        """
        if not keyword:
            return reports
            
        keyword_lower = keyword.lower()
        filtered_reports = []
        
        for report in reports:
            match_found = False
            
            try:
                # Search in target name
                target = report.get('target', '')
                if isinstance(target, str) and keyword_lower in target.lower():
                    match_found = True
                
                # Search in subdomains
                if not match_found:
                    subdomains = report.get('subdomains', [])
                    if isinstance(subdomains, list):
                        for subdomain in subdomains:
                            if isinstance(subdomain, str) and keyword_lower in subdomain.lower():
                                match_found = True
                                break
                
                # Search in vulnerability descriptions and titles
                if not match_found:
                    vulnerabilities = report.get('vulnerabilities', [])
                    if isinstance(vulnerabilities, list):
                        for vuln in vulnerabilities:
                            if isinstance(vuln, dict):
                                # Search in title
                                title = vuln.get('title', '')
                                if isinstance(title, str) and keyword_lower in title.lower():
                                    match_found = True
                                    break
                                
                                # Search in description
                                description = vuln.get('description', '')
                                if isinstance(description, str) and keyword_lower in description.lower():
                                    match_found = True
                                    break
                                
                                # Search in affected service
                                affected_service = vuln.get('affected_service', '')
                                if isinstance(affected_service, str) and keyword_lower in affected_service.lower():
                                    match_found = True
                                    break
                
                # Search in open ports services
                if not match_found:
                    open_ports = report.get('open_ports', {})
                    if isinstance(open_ports, dict):
                        for port, service in open_ports.items():
                            if isinstance(service, str) and keyword_lower in service.lower():
                                match_found = True
                                break
                            if isinstance(port, str) and keyword_lower in port.lower():
                                match_found = True
                                break
                
                if match_found:
                    filtered_reports.append(report)
                    
            except Exception as e:
                self.logger.warning(f"Error searching in report: {str(e)}")
                continue
                
        return filtered_reports


def get_subdomain_counts(reports: List[Dict]) -> Dict[str, int]:
    """
    Convenience function to get subdomain counts per target.
    
    Args:
        reports: List of report dictionaries
        
    Returns:
        Dictionary mapping target names to subdomain counts
    """
    analytics = ReportAnalytics()
    return analytics.get_subdomain_counts(reports)


def get_port_distribution(reports: List[Dict]) -> Dict[str, int]:
    """
    Convenience function to get port distribution across all reports.
    
    Args:
        reports: List of report dictionaries
        
    Returns:
        Dictionary mapping port numbers to occurrence counts
    """
    analytics = ReportAnalytics()
    return analytics.get_port_distribution(reports)


def get_timeline_data(reports: List[Dict]) -> List[Tuple[str, int]]:
    """
    Convenience function to get timeline data.
    
    Args:
        reports: List of report dictionaries
        
    Returns:
        List of tuples containing (date_string, report_count)
    """
    analytics = ReportAnalytics()
    return analytics.get_timeline_data(reports)