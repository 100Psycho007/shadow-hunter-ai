"""
Data loading and validation module for AI Threat Hunting Dashboard.

This module handles loading JSON reconnaissance reports from the local filesystem,
validating their structure, and providing error handling for malformed files.
"""

import json
import os
import logging
from typing import List, Dict, Optional
from pathlib import Path


class ReportLoader:
    """
    Handles loading and validation of JSON reconnaissance reports.
    
    This class provides functionality to scan directories for JSON files,
    parse them according to the expected schema, and validate their structure.
    """
    
    def __init__(self):
        """Initialize the ReportLoader."""
        self.logger = logging.getLogger(__name__)
        
    def load_reports(self, directory_path: str) -> List[Dict]:
        """
        Load all JSON reports from the specified directory.
        
        Args:
            directory_path: Path to the directory containing JSON report files
            
        Returns:
            List of parsed and validated report dictionaries
        """
        reports = []
        
        # Check if directory exists
        if not os.path.exists(directory_path):
            self.logger.warning(f"Reports directory does not exist: {directory_path}")
            return reports
            
        # Get all JSON files in the directory
        json_files = self.get_report_files(directory_path)
        
        if not json_files:
            self.logger.info(f"No JSON files found in directory: {directory_path}")
            return reports
            
        # Process each JSON file
        for file_path in json_files:
            try:
                report = self._parse_json_report(file_path)
                if report and self.validate_report_schema(report):
                    reports.append(report)
                    self.logger.debug(f"Successfully loaded report: {file_path}")
                else:
                    self.logger.warning(f"Invalid report schema in file: {file_path}")
            except Exception as e:
                self.logger.error(f"Error processing file {file_path}: {str(e)}")
                continue
                
        self.logger.info(f"Loaded {len(reports)} valid reports from {len(json_files)} files")
        return reports
    
    def get_report_files(self, directory_path: str) -> List[str]:
        """
        Get list of JSON files in the specified directory.
        
        Args:
            directory_path: Path to scan for JSON files
            
        Returns:
            List of full file paths to JSON files
        """
        json_files = []
        
        try:
            for filename in os.listdir(directory_path):
                if filename.lower().endswith('.json'):
                    file_path = os.path.join(directory_path, filename)
                    json_files.append(file_path)
        except OSError as e:
            self.logger.error(f"Error accessing directory {directory_path}: {str(e)}")
            
        return json_files
    
    def _parse_json_report(self, file_path: str) -> Optional[Dict]:
        """
        Parse a single JSON report file.
        
        Args:
            file_path: Path to the JSON file to parse
            
        Returns:
            Parsed JSON data as dictionary, or None if parsing fails
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                return data
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in file {file_path}: {str(e)}")
            return None
        except FileNotFoundError:
            self.logger.error(f"File not found: {file_path}")
            return None
        except PermissionError:
            self.logger.error(f"Permission denied reading file: {file_path}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error reading file {file_path}: {str(e)}")
            return None
    
    def validate_report_schema(self, report: Dict) -> bool:
        """
        Validate that a report dictionary matches the expected schema.
        
        Expected schema:
        {
            "target": str,
            "scan_date": str,
            "subdomains": List[str],
            "open_ports": Dict[str, str],
            "vulnerabilities": List[Dict],
            "ai_summary": Optional[str]
        }
        
        Args:
            report: Dictionary to validate
            
        Returns:
            True if the report matches the expected schema, False otherwise
        """
        if not isinstance(report, dict):
            self.logger.error("Report is not a dictionary")
            return False
            
        # Check required fields
        required_fields = ['target', 'scan_date', 'subdomains', 'open_ports', 'vulnerabilities']
        
        for field in required_fields:
            if field not in report:
                self.logger.error(f"Missing required field: {field}")
                return False
                
        # Validate field types
        try:
            # target should be a string
            if not isinstance(report['target'], str) or not report['target'].strip():
                self.logger.error("Field 'target' must be a non-empty string")
                return False
                
            # scan_date should be a string
            if not isinstance(report['scan_date'], str) or not report['scan_date'].strip():
                self.logger.error("Field 'scan_date' must be a non-empty string")
                return False
                
            # subdomains should be a list of strings
            if not isinstance(report['subdomains'], list):
                self.logger.error("Field 'subdomains' must be a list")
                return False
            for subdomain in report['subdomains']:
                if not isinstance(subdomain, str):
                    self.logger.error("All subdomains must be strings")
                    return False
                    
            # open_ports should be a dictionary with string keys and values
            if not isinstance(report['open_ports'], dict):
                self.logger.error("Field 'open_ports' must be a dictionary")
                return False
            for port, service in report['open_ports'].items():
                if not isinstance(port, str) or not isinstance(service, str):
                    self.logger.error("All open_ports keys and values must be strings")
                    return False
                    
            # vulnerabilities should be a list of dictionaries
            if not isinstance(report['vulnerabilities'], list):
                self.logger.error("Field 'vulnerabilities' must be a list")
                return False
            for vuln in report['vulnerabilities']:
                if not isinstance(vuln, dict):
                    self.logger.error("All vulnerabilities must be dictionaries")
                    return False
                    
            # ai_summary is optional but should be string or None if present
            if 'ai_summary' in report:
                if report['ai_summary'] is not None and not isinstance(report['ai_summary'], str):
                    self.logger.error("Field 'ai_summary' must be a string or None")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Error validating report schema: {str(e)}")
            return False
            
        return True


def parse_json_report(file_path: str) -> Optional[Dict]:
    """
    Convenience function to parse a single JSON report file.
    
    Args:
        file_path: Path to the JSON file to parse
        
    Returns:
        Parsed JSON data as dictionary, or None if parsing fails
    """
    loader = ReportLoader()
    return loader._parse_json_report(file_path)