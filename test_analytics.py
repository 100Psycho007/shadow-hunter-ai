#!/usr/bin/env python3
"""
Unit tests for the analytics module.

Tests KPI calculation, filtering logic, and data processing functionality.
"""

import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, date
import sys
import os

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from analytics import ReportAnalytics


class TestReportAnalytics(unittest.TestCase):
    """Test cases for ReportAnalytics class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analytics = ReportAnalytics()
        
        # Sample test data
        self.sample_reports = [
            {
                "target": "example.com",
                "scan_date": "2025-01-15",
                "subdomains": ["www.example.com", "api.example.com", "admin.example.com"],
                "open_ports": {"80": "http", "443": "https", "22": "ssh"},
                "vulnerabilities": [
                    {
                        "severity": "high",
                        "title": "SQL Injection",
                        "description": "Potential SQL injection vulnerability",
                        "affected_service": "http"
                    },
                    {
                        "severity": "medium",
                        "title": "Outdated Software",
                        "description": "Web server running outdated version",
                        "affected_service": "https"
                    }
                ]
            },
            {
                "target": "test.org",
                "scan_date": "2025-01-16",
                "subdomains": ["mail.test.org", "ftp.test.org"],
                "open_ports": {"25": "smtp", "21": "ftp", "80": "http"},
                "vulnerabilities": [
                    {
                        "severity": "critical",
                        "title": "Remote Code Execution",
                        "description": "Critical RCE vulnerability",
                        "affected_service": "ftp"
                    }
                ]
            }
        ]
    
    def test_calculate_kpis_valid_data(self):
        """Test KPI calculation with valid data."""
        kpis = self.analytics.calculate_kpis(self.sample_reports)
        
        self.assertEqual(kpis['total_reports'], 2)
        self.assertEqual(kpis['total_subdomains'], 5)  # 3 + 2 unique subdomains
        self.assertEqual(kpis['avg_open_ports'], 3.0)  # (3 + 3) / 2
        self.assertEqual(kpis['total_vulnerabilities'], 3)  # 2 + 1
    
    def test_calculate_kpis_empty_data(self):
        """Test KPI calculation with empty data."""
        kpis = self.analytics.calculate_kpis([])
        
        self.assertEqual(kpis['total_reports'], 0)
        self.assertEqual(kpis['total_subdomains'], 0)
        self.assertEqual(kpis['avg_open_ports'], 0.0)
        self.assertEqual(kpis['total_vulnerabilities'], 0)
    
    def test_calculate_kpis_malformed_data(self):
        """Test KPI calculation with malformed data."""
        malformed_reports = [
            {"target": "example.com"},  # Missing required fields
            None,  # None report
            {"target": "test.com", "subdomains": "not_a_list"},  # Wrong data type
        ]
        
        kpis = self.analytics.calculate_kpis(malformed_reports)
        
        # Should handle errors gracefully
        self.assertEqual(kpis['total_reports'], 3)
        self.assertEqual(kpis['total_subdomains'], 0)
        self.assertEqual(kpis['avg_open_ports'], 0.0)
        self.assertEqual(kpis['total_vulnerabilities'], 0)
    
    def test_get_subdomain_counts(self):
        """Test subdomain count calculation."""
        counts = self.analytics.get_subdomain_counts(self.sample_reports)
        
        self.assertEqual(counts['example.com'], 3)
        self.assertEqual(counts['test.org'], 2)
    
    def test_get_subdomain_counts_invalid_data(self):
        """Test subdomain count with invalid data."""
        invalid_reports = [
            {"target": "example.com", "subdomains": "not_a_list"},
            {"target": "test.com"},  # Missing subdomains
        ]
        
        counts = self.analytics.get_subdomain_counts(invalid_reports)
        
        self.assertEqual(counts['example.com'], 0)
        self.assertEqual(counts['test.com'], 0)
    
    def test_get_port_distribution(self):
        """Test port distribution calculation."""
        distribution = self.analytics.get_port_distribution(self.sample_reports)
        
        self.assertEqual(distribution['80'], 2)  # Appears in both reports
        self.assertEqual(distribution['443'], 1)  # Only in first report
        self.assertEqual(distribution['25'], 1)   # Only in second report
    
    def test_get_timeline_data(self):
        """Test timeline data generation."""
        timeline = self.analytics.get_timeline_data(self.sample_reports)
        
        # Should return sorted list of (date, count) tuples
        self.assertEqual(len(timeline), 2)
        self.assertEqual(timeline[0], ('2025-01-15', 1))
        self.assertEqual(timeline[1], ('2025-01-16', 1))
    
    def test_get_timeline_data_invalid_dates(self):
        """Test timeline data with invalid dates."""
        invalid_reports = [
            {"target": "example.com", "scan_date": "invalid-date"},
            {"target": "test.com", "scan_date": ""},
            {"target": "another.com"},  # Missing scan_date
        ]
        
        timeline = self.analytics.get_timeline_data(invalid_reports)
        
        # Should handle invalid dates gracefully
        self.assertEqual(len(timeline), 0)
    
    def test_filter_reports_by_targets(self):
        """Test filtering reports by target names."""
        filters = {
            'selected_targets': ['example.com'],
            'date_range': None,
            'keyword_search': '',
            'show_ai_summaries': None
        }
        
        filtered = self.analytics.filter_reports(self.sample_reports, filters)
        
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['target'], 'example.com')
    
    def test_filter_reports_by_keyword(self):
        """Test filtering reports by keyword search."""
        filters = {
            'selected_targets': [],
            'date_range': None,
            'keyword_search': 'sql injection',
            'show_ai_summaries': None
        }
        
        filtered = self.analytics.filter_reports(self.sample_reports, filters)
        
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['target'], 'example.com')
    
    def test_filter_reports_by_date_range(self):
        """Test filtering reports by date range."""
        start_date = date(2025, 1, 15)
        end_date = date(2025, 1, 15)
        
        filters = {
            'selected_targets': [],
            'date_range': (start_date, end_date),
            'keyword_search': '',
            'show_ai_summaries': None
        }
        
        filtered = self.analytics.filter_reports(self.sample_reports, filters)
        
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]['target'], 'example.com')
    
    def test_filter_reports_empty_filters(self):
        """Test filtering with empty/None filters."""
        filters = {
            'selected_targets': [],
            'date_range': None,
            'keyword_search': '',
            'show_ai_summaries': None
        }
        
        filtered = self.analytics.filter_reports(self.sample_reports, filters)
        
        # Should return all reports when no filters applied
        self.assertEqual(len(filtered), 2)
    
    def test_get_unique_targets(self):
        """Test unique target extraction."""
        targets = self.analytics.get_unique_targets(self.sample_reports)
        
        self.assertEqual(set(targets), {'example.com', 'test.org'})
        self.assertEqual(targets, sorted(targets))  # Should be sorted
    
    def test_get_date_range(self):
        """Test date range calculation."""
        min_date, max_date = self.analytics.get_date_range(self.sample_reports)
        
        self.assertEqual(min_date.date(), date(2025, 1, 15))
        self.assertEqual(max_date.date(), date(2025, 1, 16))
    
    def test_get_date_range_no_valid_dates(self):
        """Test date range with no valid dates."""
        invalid_reports = [
            {"target": "example.com", "scan_date": "invalid"},
            {"target": "test.com"}  # Missing date
        ]
        
        min_date, max_date = self.analytics.get_date_range(invalid_reports)
        
        self.assertIsNone(min_date)
        self.assertIsNone(max_date)
    
    def test_generate_chart_data(self):
        """Test comprehensive chart data generation."""
        chart_data = self.analytics.generate_chart_data(self.sample_reports)
        
        self.assertIn('subdomain_counts', chart_data)
        self.assertIn('port_distribution', chart_data)
        self.assertIn('timeline_data', chart_data)
        
        # Verify data structure
        self.assertEqual(chart_data['subdomain_counts']['example.com'], 3)
        self.assertEqual(chart_data['port_distribution']['80'], 2)
        self.assertEqual(len(chart_data['timeline_data']), 2)
    
    def test_error_handling_graceful(self):
        """Test that errors are handled gracefully."""
        # Force an error by passing None
        kpis = self.analytics.calculate_kpis(None)
        
        # Should return default values instead of crashing
        self.assertEqual(kpis['total_reports'], 0)
        self.assertEqual(kpis['total_subdomains'], 0)
        self.assertEqual(kpis['avg_open_ports'], 0.0)
        self.assertEqual(kpis['total_vulnerabilities'], 0)


class TestAnalyticsEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analytics = ReportAnalytics()
    
    def test_large_dataset_performance(self):
        """Test performance with large dataset."""
        # Create a large dataset
        large_reports = []
        for i in range(1000):
            report = {
                "target": f"target{i}.com",
                "scan_date": "2025-01-15",
                "subdomains": [f"sub{j}.target{i}.com" for j in range(10)],
                "open_ports": {"80": "http", "443": "https"},
                "vulnerabilities": []
            }
            large_reports.append(report)
        
        # Should handle large datasets without errors
        kpis = self.analytics.calculate_kpis(large_reports)
        
        self.assertEqual(kpis['total_reports'], 1000)
        self.assertEqual(kpis['total_subdomains'], 10000)  # 1000 * 10 unique subdomains
    
    def test_unicode_and_special_characters(self):
        """Test handling of unicode and special characters."""
        unicode_reports = [
            {
                "target": "测试.com",
                "scan_date": "2025-01-15",
                "subdomains": ["子域名.测试.com"],
                "open_ports": {"80": "http"},
                "vulnerabilities": [
                    {
                        "severity": "high",
                        "title": "Vulnerability with émojis 🚨",
                        "description": "Description with special chars: <>&\"'",
                        "affected_service": "http"
                    }
                ]
            }
        ]
        
        # Should handle unicode without errors
        kpis = self.analytics.calculate_kpis(unicode_reports)
        self.assertEqual(kpis['total_reports'], 1)
        
        # Test filtering with unicode
        filters = {
            'selected_targets': [],
            'keyword_search': '测试',
            'date_range': None,
            'show_ai_summaries': None
        }
        
        filtered = self.analytics.filter_reports(unicode_reports, filters)
        self.assertEqual(len(filtered), 1)
    
    def test_concurrent_access_safety(self):
        """Test thread safety (basic check)."""
        import threading
        
        results = []
        
        def calculate_kpis():
            kpis = self.analytics.calculate_kpis([
                {
                    "target": "example.com",
                    "scan_date": "2025-01-15",
                    "subdomains": ["www.example.com"],
                    "open_ports": {"80": "http"},
                    "vulnerabilities": []
                }
            ])
            results.append(kpis)
        
        # Run multiple threads
        threads = [threading.Thread(target=calculate_kpis) for _ in range(10)]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # All results should be identical
        self.assertEqual(len(results), 10)
        for result in results:
            self.assertEqual(result['total_reports'], 1)


if __name__ == '__main__':
    unittest.main()