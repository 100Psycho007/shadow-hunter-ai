#!/usr/bin/env python3
"""
Unit tests for the data loading module.

Tests JSON parsing, schema validation, and error handling functionality.
"""

import unittest
from unittest.mock import patch, mock_open, MagicMock
import json
import os
import sys
import tempfile
import shutil

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from loader import ReportLoader, parse_json_report


class TestReportLoader(unittest.TestCase):
    """Test cases for ReportLoader class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.loader = ReportLoader()
        
        # Valid sample report
        self.valid_report = {
            "target": "example.com",
            "scan_date": "2025-01-15",
            "subdomains": ["www.example.com", "api.example.com", "admin.example.com"],
            "open_ports": {"80": "http", "443": "https", "22": "ssh"},
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
        
        # Create temporary directory for testing
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        # Remove temporary directory
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_validate_report_schema_valid(self):
        """Test schema validation with valid report."""
        result = self.loader.validate_report_schema(self.valid_report)
        self.assertTrue(result)
    
    def test_validate_report_schema_missing_required_fields(self):
        """Test schema validation with missing required fields."""
        # Missing target
        invalid_report = self.valid_report.copy()
        del invalid_report['target']
        
        result = self.loader.validate_report_schema(invalid_report)
        self.assertFalse(result)
        
        # Missing scan_date
        invalid_report = self.valid_report.copy()
        del invalid_report['scan_date']
        
        result = self.loader.validate_report_schema(invalid_report)
        self.assertFalse(result)
        
        # Missing subdomains
        invalid_report = self.valid_report.copy()
        del invalid_report['subdomains']
        
        result = self.loader.validate_report_schema(invalid_report)
        self.assertFalse(result)
    
    def test_validate_report_schema_wrong_types(self):
        """Test schema validation with wrong data types."""
        # Target not a string
        invalid_report = self.valid_report.copy()
        invalid_report['target'] = 123
        
        result = self.loader.validate_report_schema(invalid_report)
        self.assertFalse(result)
        
        # Subdomains not a list
        invalid_report = self.valid_report.copy()
        invalid_report['subdomains'] = "not_a_list"
        
        result = self.loader.validate_report_schema(invalid_report)
        self.assertFalse(result)
        
        # Open ports not a dictionary
        invalid_report = self.valid_report.copy()
        invalid_report['open_ports'] = ["80", "443"]
        
        result = self.loader.validate_report_schema(invalid_report)
        self.assertFalse(result)
        
        # Vulnerabilities not a list
        invalid_report = self.valid_report.copy()
        invalid_report['vulnerabilities'] = "not_a_list"
        
        result = self.loader.validate_report_schema(invalid_report)
        self.assertFalse(result)
    
    def test_validate_report_schema_empty_required_fields(self):
        """Test schema validation with empty required fields."""
        # Empty target
        invalid_report = self.valid_report.copy()
        invalid_report['target'] = ""
        
        result = self.loader.validate_report_schema(invalid_report)
        self.assertFalse(result)
        
        # Empty scan_date
        invalid_report = self.valid_report.copy()
        invalid_report['scan_date'] = ""
        
        result = self.loader.validate_report_schema(invalid_report)
        self.assertFalse(result)
    
    def test_validate_report_schema_invalid_subdomain_types(self):
        """Test schema validation with invalid subdomain types."""
        invalid_report = self.valid_report.copy()
        invalid_report['subdomains'] = ["valid.com", 123, "another.com"]
        
        result = self.loader.validate_report_schema(invalid_report)
        self.assertFalse(result)
    
    def test_validate_report_schema_invalid_port_types(self):
        """Test schema validation with invalid port types."""
        invalid_report = self.valid_report.copy()
        invalid_report['open_ports'] = {80: "http", "443": "https"}  # Key should be string
        
        result = self.loader.validate_report_schema(invalid_report)
        self.assertFalse(result)
        
        invalid_report['open_ports'] = {"80": 80, "443": "https"}  # Value should be string
        
        result = self.loader.validate_report_schema(invalid_report)
        self.assertFalse(result)
    
    def test_validate_report_schema_invalid_vulnerability_types(self):
        """Test schema validation with invalid vulnerability types."""
        invalid_report = self.valid_report.copy()
        invalid_report['vulnerabilities'] = ["not_a_dict", {"valid": "dict"}]
        
        result = self.loader.validate_report_schema(invalid_report)
        self.assertFalse(result)
    
    def test_validate_report_schema_optional_ai_summary(self):
        """Test schema validation with optional AI summary field."""
        # Valid with string AI summary
        report_with_ai = self.valid_report.copy()
        report_with_ai['ai_summary'] = "This is an AI summary"
        
        result = self.loader.validate_report_schema(report_with_ai)
        self.assertTrue(result)
        
        # Valid with None AI summary
        report_with_none_ai = self.valid_report.copy()
        report_with_none_ai['ai_summary'] = None
        
        result = self.loader.validate_report_schema(report_with_none_ai)
        self.assertTrue(result)
        
        # Invalid with non-string AI summary
        report_with_invalid_ai = self.valid_report.copy()
        report_with_invalid_ai['ai_summary'] = 123
        
        result = self.loader.validate_report_schema(report_with_invalid_ai)
        self.assertFalse(result)
    
    def test_validate_report_schema_not_dict(self):
        """Test schema validation with non-dictionary input."""
        result = self.loader.validate_report_schema("not_a_dict")
        self.assertFalse(result)
        
        result = self.loader.validate_report_schema(None)
        self.assertFalse(result)
        
        result = self.loader.validate_report_schema([])
        self.assertFalse(result)
    
    def test_parse_json_report_valid(self):
        """Test parsing valid JSON report file."""
        # Create temporary JSON file
        json_file = os.path.join(self.test_dir, "valid_report.json")
        with open(json_file, 'w') as f:
            json.dump(self.valid_report, f)
        
        result = self.loader._parse_json_report(json_file)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['target'], 'example.com')
        self.assertEqual(len(result['subdomains']), 3)
    
    def test_parse_json_report_invalid_json(self):
        """Test parsing invalid JSON file."""
        # Create temporary file with invalid JSON
        json_file = os.path.join(self.test_dir, "invalid.json")
        with open(json_file, 'w') as f:
            f.write('{"invalid": json}')  # Missing quotes around json
        
        result = self.loader._parse_json_report(json_file)
        self.assertIsNone(result)
    
    def test_parse_json_report_file_not_found(self):
        """Test parsing non-existent file."""
        result = self.loader._parse_json_report("non_existent_file.json")
        self.assertIsNone(result)
    
    @patch('builtins.open', side_effect=PermissionError("Permission denied"))
    def test_parse_json_report_permission_error(self, mock_open):
        """Test parsing file with permission error."""
        result = self.loader._parse_json_report("restricted_file.json")
        self.assertIsNone(result)
    
    def test_get_report_files(self):
        """Test getting list of JSON files from directory."""
        # Create test files
        json_file1 = os.path.join(self.test_dir, "report1.json")
        json_file2 = os.path.join(self.test_dir, "report2.JSON")  # Test case insensitive
        txt_file = os.path.join(self.test_dir, "not_json.txt")
        
        with open(json_file1, 'w') as f:
            json.dump({"test": "data"}, f)
        with open(json_file2, 'w') as f:
            json.dump({"test": "data"}, f)
        with open(txt_file, 'w') as f:
            f.write("not json")
        
        files = self.loader.get_report_files(self.test_dir)
        
        self.assertEqual(len(files), 2)
        self.assertIn(json_file1, files)
        self.assertIn(json_file2, files)
        self.assertNotIn(txt_file, files)
    
    def test_get_report_files_nonexistent_directory(self):
        """Test getting files from non-existent directory."""
        files = self.loader.get_report_files("non_existent_directory")
        self.assertEqual(len(files), 0)
    
    def test_load_reports_valid_directory(self):
        """Test loading reports from directory with valid files."""
        # Create test JSON files
        report1 = self.valid_report.copy()
        report1['target'] = 'test1.com'
        
        report2 = self.valid_report.copy()
        report2['target'] = 'test2.com'
        
        json_file1 = os.path.join(self.test_dir, "report1.json")
        json_file2 = os.path.join(self.test_dir, "report2.json")
        
        with open(json_file1, 'w') as f:
            json.dump(report1, f)
        with open(json_file2, 'w') as f:
            json.dump(report2, f)
        
        reports = self.loader.load_reports(self.test_dir)
        
        self.assertEqual(len(reports), 2)
        targets = [r['target'] for r in reports]
        self.assertIn('test1.com', targets)
        self.assertIn('test2.com', targets)
    
    def test_load_reports_mixed_valid_invalid(self):
        """Test loading reports with mix of valid and invalid files."""
        # Create valid report
        valid_file = os.path.join(self.test_dir, "valid.json")
        with open(valid_file, 'w') as f:
            json.dump(self.valid_report, f)
        
        # Create invalid JSON
        invalid_json_file = os.path.join(self.test_dir, "invalid.json")
        with open(invalid_json_file, 'w') as f:
            f.write('{"invalid": json}')
        
        # Create valid JSON but invalid schema
        invalid_schema_file = os.path.join(self.test_dir, "invalid_schema.json")
        with open(invalid_schema_file, 'w') as f:
            json.dump({"missing": "required_fields"}, f)
        
        reports = self.loader.load_reports(self.test_dir)
        
        # Should only load the valid report
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]['target'], 'example.com')
    
    def test_load_reports_empty_directory(self):
        """Test loading reports from empty directory."""
        reports = self.loader.load_reports(self.test_dir)
        self.assertEqual(len(reports), 0)
    
    def test_load_reports_nonexistent_directory(self):
        """Test loading reports from non-existent directory."""
        reports = self.loader.load_reports("non_existent_directory")
        self.assertEqual(len(reports), 0)
    
    def test_load_reports_no_json_files(self):
        """Test loading reports from directory with no JSON files."""
        # Create non-JSON file
        txt_file = os.path.join(self.test_dir, "not_json.txt")
        with open(txt_file, 'w') as f:
            f.write("This is not JSON")
        
        reports = self.loader.load_reports(self.test_dir)
        self.assertEqual(len(reports), 0)
    
    @patch('loader.logging.getLogger')
    def test_logging_functionality(self, mock_get_logger):
        """Test that appropriate log messages are generated."""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger
        
        # Create new loader to use mocked logger
        loader = ReportLoader()
        
        # Test loading from non-existent directory
        loader.load_reports("non_existent")
        mock_logger.warning.assert_called()
        
        # Test loading with no JSON files
        loader.load_reports(self.test_dir)
        mock_logger.info.assert_called()


class TestParseJsonReportFunction(unittest.TestCase):
    """Test the standalone parse_json_report function."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.valid_report = {
            "target": "example.com",
            "scan_date": "2025-01-15",
            "subdomains": ["www.example.com"],
            "open_ports": {"80": "http"},
            "vulnerabilities": []
        }
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_parse_json_report_function(self):
        """Test the standalone parse_json_report function."""
        # Create test file
        json_file = os.path.join(self.test_dir, "test.json")
        with open(json_file, 'w') as f:
            json.dump(self.valid_report, f)
        
        result = parse_json_report(json_file)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['target'], 'example.com')
    
    def test_parse_json_report_function_invalid(self):
        """Test the standalone function with invalid file."""
        result = parse_json_report("non_existent.json")
        self.assertIsNone(result)


class TestReportLoaderEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.loader = ReportLoader()
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_large_json_file(self):
        """Test handling of large JSON files."""
        # Create a large report with many subdomains
        large_report = {
            "target": "large.com",
            "scan_date": "2025-01-15",
            "subdomains": [f"sub{i}.large.com" for i in range(10000)],
            "open_ports": {str(i): f"service{i}" for i in range(80, 90)},
            "vulnerabilities": [
                {
                    "severity": "medium",
                    "title": f"Vulnerability {i}",
                    "description": f"Description for vulnerability {i}",
                    "affected_service": "http"
                }
                for i in range(100)
            ]
        }
        
        json_file = os.path.join(self.test_dir, "large.json")
        with open(json_file, 'w') as f:
            json.dump(large_report, f)
        
        # Should handle large files without issues
        result = self.loader._parse_json_report(json_file)
        self.assertIsNotNone(result)
        self.assertEqual(len(result['subdomains']), 10000)
        self.assertEqual(len(result['vulnerabilities']), 100)
    
    def test_unicode_content(self):
        """Test handling of Unicode content in JSON files."""
        unicode_report = {
            "target": "测试.com",
            "scan_date": "2025-01-15",
            "subdomains": ["子域名.测试.com", "另一个.测试.com"],
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
        
        json_file = os.path.join(self.test_dir, "unicode.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(unicode_report, f, ensure_ascii=False)
        
        result = self.loader._parse_json_report(json_file)
        self.assertIsNotNone(result)
        self.assertEqual(result['target'], '测试.com')
        self.assertIn('🚨', result['vulnerabilities'][0]['title'])
    
    def test_deeply_nested_vulnerabilities(self):
        """Test handling of complex vulnerability structures."""
        complex_report = {
            "target": "complex.com",
            "scan_date": "2025-01-15",
            "subdomains": ["www.complex.com"],
            "open_ports": {"80": "http"},
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "title": "Complex Vulnerability",
                    "description": "A very long description " * 100,  # Very long description
                    "affected_service": "http",
                    "cve_id": "CVE-2023-1234",
                    "additional_data": {
                        "nested": {
                            "deeply": {
                                "nested": "data"
                            }
                        }
                    }
                }
            ]
        }
        
        json_file = os.path.join(self.test_dir, "complex.json")
        with open(json_file, 'w') as f:
            json.dump(complex_report, f)
        
        result = self.loader._parse_json_report(json_file)
        self.assertIsNotNone(result)
        
        # Schema validation should still pass (additional fields are allowed)
        valid = self.loader.validate_report_schema(result)
        self.assertTrue(valid)
    
    def test_concurrent_file_access(self):
        """Test concurrent access to the same file."""
        import threading
        
        # Create test file
        json_file = os.path.join(self.test_dir, "concurrent.json")
        test_report = {
            "target": "concurrent.com",
            "scan_date": "2025-01-15",
            "subdomains": ["www.concurrent.com"],
            "open_ports": {"80": "http"},
            "vulnerabilities": []
        }
        
        with open(json_file, 'w') as f:
            json.dump(test_report, f)
        
        results = []
        
        def parse_file():
            result = self.loader._parse_json_report(json_file)
            results.append(result)
        
        # Create multiple threads to access the same file
        threads = [threading.Thread(target=parse_file) for _ in range(10)]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # All threads should successfully parse the file
        self.assertEqual(len(results), 10)
        for result in results:
            self.assertIsNotNone(result)
            self.assertEqual(result['target'], 'concurrent.com')


if __name__ == '__main__':
    unittest.main()