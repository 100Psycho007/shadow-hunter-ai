#!/usr/bin/env python3
"""
Unit tests for the AI integration module.

Tests API key detection, summary generation, caching, and error handling.
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import json
import os
import sys
import requests

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from ai import AIAnalyzer, ReportAICache, EnhancedAIAnalyzer


class TestAIAnalyzer(unittest.TestCase):
    """Test cases for AIAnalyzer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.sample_report = {
            "target": "example.com",
            "scan_date": "2025-01-15",
            "subdomains": ["www.example.com", "api.example.com"],
            "open_ports": {"80": "http", "443": "https"},
            "vulnerabilities": [
                {
                    "severity": "high",
                    "title": "SQL Injection",
                    "description": "Potential SQL injection vulnerability",
                    "affected_service": "http"
                }
            ]
        }
    
    @patch.dict(os.environ, {'OPENROUTER_API_KEY': 'test-api-key'})
    def test_api_key_from_environment(self):
        """Test API key detection from environment variable."""
        analyzer = AIAnalyzer()
        
        self.assertTrue(analyzer.is_enabled())
        self.assertEqual(analyzer.api_key, 'test-api-key')
    
    @patch.dict(os.environ, {}, clear=True)
    def test_no_api_key(self):
        """Test behavior when no API key is provided."""
        analyzer = AIAnalyzer()
        
        self.assertFalse(analyzer.is_enabled())
        self.assertIsNone(analyzer.api_key)
    
    def test_api_key_override(self):
        """Test API key override in constructor."""
        analyzer = AIAnalyzer(api_key='override-key')
        
        self.assertTrue(analyzer.is_enabled())
        self.assertEqual(analyzer.api_key, 'override-key')
    
    def test_format_prompt(self):
        """Test prompt formatting for AI analysis."""
        analyzer = AIAnalyzer(api_key='test-key')
        prompt = analyzer.format_prompt(self.sample_report)
        
        self.assertIn('example.com', prompt)
        self.assertIn('2025-01-15', prompt)
        self.assertIn('www.example.com', prompt)
        self.assertIn('80(http)', prompt)
        self.assertIn('SQL Injection', prompt)
        self.assertIn('RISK LEVEL', prompt)
        self.assertIn('RECOMMENDATIONS', prompt)
    
    def test_format_prompt_empty_data(self):
        """Test prompt formatting with minimal data."""
        minimal_report = {
            "target": "test.com",
            "scan_date": "2025-01-15",
            "subdomains": [],
            "open_ports": {},
            "vulnerabilities": []
        }
        
        analyzer = AIAnalyzer(api_key='test-key')
        prompt = analyzer.format_prompt(minimal_report)
        
        self.assertIn('test.com', prompt)
        self.assertIn('(0)', prompt)  # Should show 0 counts
    
    def test_cache_key_generation(self):
        """Test cache key generation for reports."""
        analyzer = AIAnalyzer(api_key='test-key')
        
        key1 = analyzer._generate_cache_key(self.sample_report)
        key2 = analyzer._generate_cache_key(self.sample_report)
        
        # Same report should generate same key
        self.assertEqual(key1, key2)
        
        # Different report should generate different key
        different_report = self.sample_report.copy()
        different_report['target'] = 'different.com'
        key3 = analyzer._generate_cache_key(different_report)
        
        self.assertNotEqual(key1, key3)
    
    @patch('ai.requests.Session.post')
    def test_successful_api_call(self, mock_post):
        """Test successful AI summary generation."""
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "RISK LEVEL: High\nKEY CONCERNS: SQL injection vulnerability\nRECOMMENDATIONS: Patch immediately"
                    }
                }
            ]
        }
        mock_post.return_value = mock_response
        
        analyzer = AIAnalyzer(api_key='test-key')
        summary = analyzer.generate_summary(self.sample_report)
        
        self.assertIsNotNone(summary)
        self.assertIn('RISK LEVEL: High', summary)
        self.assertIn('SQL injection', summary)
        
        # Verify API was called with correct parameters
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertIn('json', call_args.kwargs)
        self.assertEqual(call_args.kwargs['json']['model'], 'anthropic/claude-3-haiku')
    
    @patch('ai.requests.Session.post')
    def test_api_error_handling(self, mock_post):
        """Test handling of various API errors."""
        analyzer = AIAnalyzer(api_key='test-key')
        
        # Test 401 Unauthorized
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response
        
        summary = analyzer.generate_summary(self.sample_report)
        self.assertIsNone(summary)
        
        # Test 429 Rate Limit
        mock_response.status_code = 429
        summary = analyzer.generate_summary(self.sample_report)
        self.assertIsNone(summary)
        
        # Test 402 Payment Required
        mock_response.status_code = 402
        summary = analyzer.generate_summary(self.sample_report)
        self.assertIsNone(summary)
        
        # Test 500 Server Error
        mock_response.status_code = 500
        summary = analyzer.generate_summary(self.sample_report)
        self.assertIsNone(summary)
    
    @patch('ai.requests.Session.post')
    def test_network_error_handling(self, mock_post):
        """Test handling of network errors."""
        analyzer = AIAnalyzer(api_key='test-key')
        
        # Test timeout
        mock_post.side_effect = requests.exceptions.Timeout()
        summary = analyzer.generate_summary(self.sample_report)
        self.assertIsNone(summary)
        
        # Test connection error
        mock_post.side_effect = requests.exceptions.ConnectionError()
        summary = analyzer.generate_summary(self.sample_report)
        self.assertIsNone(summary)
        
        # Test generic request exception
        mock_post.side_effect = requests.exceptions.RequestException("Network error")
        summary = analyzer.generate_summary(self.sample_report)
        self.assertIsNone(summary)
    
    @patch('ai.requests.Session.post')
    def test_invalid_json_response(self, mock_post):
        """Test handling of invalid JSON responses."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_post.return_value = mock_response
        
        analyzer = AIAnalyzer(api_key='test-key')
        summary = analyzer.generate_summary(self.sample_report)
        
        self.assertIsNone(summary)
    
    @patch('ai.requests.Session.post')
    def test_caching_functionality(self, mock_post):
        """Test that results are properly cached."""
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Test summary"}}]
        }
        mock_post.return_value = mock_response
        
        analyzer = AIAnalyzer(api_key='test-key')
        
        # First call should hit API
        summary1 = analyzer.generate_summary(self.sample_report)
        self.assertEqual(summary1, "Test summary")
        self.assertEqual(mock_post.call_count, 1)
        
        # Second call should use cache
        summary2 = analyzer.generate_summary(self.sample_report)
        self.assertEqual(summary2, "Test summary")
        self.assertEqual(mock_post.call_count, 1)  # No additional API call
    
    @patch('ai.requests.Session.post')
    def test_validate_api_key(self, mock_post):
        """Test API key validation."""
        analyzer = AIAnalyzer(api_key='test-key')
        
        # Test successful validation
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        self.assertTrue(analyzer.validate_api_key())
        
        # Test failed validation
        mock_response.status_code = 401
        self.assertFalse(analyzer.validate_api_key())
        
        # Test network error during validation
        mock_post.side_effect = requests.exceptions.ConnectionError()
        self.assertFalse(analyzer.validate_api_key())
    
    def test_get_cached_summary(self):
        """Test retrieving cached summaries."""
        analyzer = AIAnalyzer(api_key='test-key')
        
        # No cache initially
        self.assertIsNone(analyzer.get_cached_summary(self.sample_report))
        
        # Add to cache manually
        cache_key = analyzer._generate_cache_key(self.sample_report)
        analyzer.cache[cache_key] = "Cached summary"
        
        # Should retrieve from cache
        cached = analyzer.get_cached_summary(self.sample_report)
        self.assertEqual(cached, "Cached summary")
    
    def test_clear_cache(self):
        """Test cache clearing functionality."""
        analyzer = AIAnalyzer(api_key='test-key')
        
        # Add something to cache
        cache_key = analyzer._generate_cache_key(self.sample_report)
        analyzer.cache[cache_key] = "Test summary"
        
        self.assertEqual(len(analyzer.cache), 1)
        
        # Clear cache
        analyzer.clear_cache()
        self.assertEqual(len(analyzer.cache), 0)
    
    def test_get_cache_stats(self):
        """Test cache statistics."""
        analyzer = AIAnalyzer(api_key='test-key')
        
        # Empty cache
        stats = analyzer.get_cache_stats()
        self.assertEqual(stats['cached_summaries'], 0)
        self.assertEqual(stats['total_cache_size'], 0)
        
        # Add to cache
        cache_key = analyzer._generate_cache_key(self.sample_report)
        analyzer.cache[cache_key] = "Test summary"
        
        stats = analyzer.get_cache_stats()
        self.assertEqual(stats['cached_summaries'], 1)
        self.assertEqual(stats['total_cache_size'], len("Test summary"))


class TestReportAICache(unittest.TestCase):
    """Test cases for ReportAICache class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.sample_report = {
            "target": "example.com",
            "scan_date": "2025-01-15",
            "subdomains": ["www.example.com"],
            "open_ports": {"80": "http"},
            "vulnerabilities": []
        }
    
    @patch('builtins.open', new_callable=mock_open, read_data='{"key1": {"summary": "cached", "timestamp": 1234567890, "target": "example.com"}}')
    @patch('os.path.exists', return_value=True)
    def test_load_persistent_cache(self, mock_exists, mock_file):
        """Test loading cache from persistent storage."""
        cache = ReportAICache("test_cache.json")
        
        self.assertEqual(len(cache.memory_cache), 1)
        self.assertIn("key1", cache.memory_cache)
    
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.path.exists', return_value=False)
    def test_load_persistent_cache_no_file(self, mock_exists, mock_file):
        """Test behavior when cache file doesn't exist."""
        cache = ReportAICache("test_cache.json")
        
        self.assertEqual(len(cache.memory_cache), 0)
    
    @patch('builtins.open', new_callable=mock_open)
    def test_save_persistent_cache(self, mock_file):
        """Test saving cache to persistent storage."""
        cache = ReportAICache("test_cache.json")
        cache.memory_cache = {"test": {"summary": "test", "timestamp": 123, "target": "test.com"}}
        
        cache.save_persistent_cache()
        
        mock_file.assert_called_with("test_cache.json", 'w', encoding='utf-8')
        handle = mock_file()
        handle.write.assert_called()
    
    def test_get_cache_key_consistency(self):
        """Test that cache key generation is consistent."""
        cache = ReportAICache()
        
        key1 = cache.get_cache_key(self.sample_report)
        key2 = cache.get_cache_key(self.sample_report)
        
        self.assertEqual(key1, key2)
    
    def test_cache_summary(self):
        """Test caching a summary."""
        cache = ReportAICache()
        
        cache.cache_summary(self.sample_report, "Test summary")
        
        cached = cache.get_cached_summary(self.sample_report)
        self.assertEqual(cached, "Test summary")
    
    def test_invalidate_cache(self):
        """Test cache invalidation."""
        cache = ReportAICache()
        
        # Add to cache
        cache.cache_summary(self.sample_report, "Test summary")
        self.assertIsNotNone(cache.get_cached_summary(self.sample_report))
        
        # Invalidate
        result = cache.invalidate_cache(self.sample_report)
        self.assertTrue(result)
        self.assertIsNone(cache.get_cached_summary(self.sample_report))
        
        # Try to invalidate non-existent entry
        result = cache.invalidate_cache(self.sample_report)
        self.assertFalse(result)
    
    def test_get_cache_stats(self):
        """Test cache statistics."""
        cache = ReportAICache("test_cache_stats.json")  # Use unique filename
        cache.clear_cache()  # Ensure clean state
        
        # Empty cache
        stats = cache.get_cache_stats()
        self.assertEqual(stats['cached_summaries'], 0)
        
        # Add entries
        cache.cache_summary(self.sample_report, "Test summary")
        
        stats = cache.get_cache_stats()
        self.assertEqual(stats['cached_summaries'], 1)
        self.assertIn('total_cache_size', stats)
        self.assertIn('oldest_entry', stats)
        self.assertIn('newest_entry', stats)


class TestEnhancedAIAnalyzer(unittest.TestCase):
    """Test cases for EnhancedAIAnalyzer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.sample_report = {
            "target": "example.com",
            "scan_date": "2025-01-15",
            "subdomains": ["www.example.com"],
            "open_ports": {"80": "http"},
            "vulnerabilities": []
        }
    
    @patch('ai.requests.Session.post')
    def test_generate_summary_for_report(self, mock_post):
        """Test enhanced summary generation with integrated caching."""
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Enhanced summary"}}]
        }
        mock_post.return_value = mock_response
        
        analyzer = EnhancedAIAnalyzer(api_key='test-key')
        
        # First call should generate and cache
        summary = analyzer.generate_summary_for_report(self.sample_report)
        self.assertEqual(summary, "Enhanced summary")
        
        # Second call should use cache
        summary2 = analyzer.generate_summary_for_report(self.sample_report)
        self.assertEqual(summary2, "Enhanced summary")
        self.assertEqual(mock_post.call_count, 1)  # Only one API call
    
    @patch('ai.requests.Session.post')
    def test_update_report_with_ai_summary(self, mock_post):
        """Test updating report dictionary with AI summary."""
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Report summary"}}]
        }
        mock_post.return_value = mock_response
        
        analyzer = EnhancedAIAnalyzer(api_key='test-key')
        report_copy = self.sample_report.copy()
        
        result = analyzer.update_report_with_ai_summary(report_copy)
        
        self.assertTrue(result)
        self.assertEqual(report_copy['ai_summary'], "Report summary")
    
    @patch('ai.requests.Session.post')
    def test_batch_generate_summaries(self, mock_post):
        """Test batch summary generation."""
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "Batch summary"}}]
        }
        mock_post.return_value = mock_response
        
        analyzer = EnhancedAIAnalyzer(api_key='test-key')
        
        reports = [self.sample_report.copy() for _ in range(3)]
        for i, report in enumerate(reports):
            report['target'] = f'target{i}.com'
        
        progress_calls = []
        def progress_callback(current, total, target):
            progress_calls.append((current, total, target))
        
        results = analyzer.batch_generate_summaries(reports, progress_callback=progress_callback)
        
        self.assertEqual(len(results), 3)
        self.assertEqual(len(progress_calls), 3)
        
        # Verify all reports got summaries
        for target, summary in results.items():
            self.assertEqual(summary, "Batch summary")
    
    def test_invalidate_report_cache(self):
        """Test cache invalidation for specific reports."""
        analyzer = EnhancedAIAnalyzer(api_key='test-key')
        report_copy = self.sample_report.copy()
        
        # Add AI summary to report
        report_copy['ai_summary'] = "Test summary"
        
        # Invalidate cache
        result = analyzer.invalidate_report_cache(report_copy)
        
        # AI summary should be removed from report
        self.assertNotIn('ai_summary', report_copy)
    
    def test_get_enhanced_cache_stats(self):
        """Test enhanced cache statistics."""
        analyzer = EnhancedAIAnalyzer(api_key='test-key')
        
        stats = analyzer.get_enhanced_cache_stats()
        
        self.assertIn('memory_cache', stats)
        self.assertIn('persistent_cache', stats)
        self.assertIn('total_cached_summaries', stats)


class TestAIUtilityFunctions(unittest.TestCase):
    """Test utility functions in the AI module."""
    
    @patch.dict(os.environ, {'OPENROUTER_API_KEY': 'env-key'})
    def test_check_api_key(self):
        """Test API key checking utility function."""
        from ai import check_api_key
        
        key = check_api_key()
        self.assertEqual(key, 'env-key')
    
    @patch.dict(os.environ, {}, clear=True)
    def test_check_api_key_none(self):
        """Test API key checking when no key is set."""
        from ai import check_api_key
        
        key = check_api_key()
        self.assertIsNone(key)
    
    def test_create_ai_analyzer(self):
        """Test AI analyzer factory function."""
        from ai import create_ai_analyzer
        
        analyzer = create_ai_analyzer(api_key='factory-key')
        
        self.assertIsInstance(analyzer, AIAnalyzer)
        self.assertEqual(analyzer.api_key, 'factory-key')
    
    def test_create_enhanced_ai_analyzer(self):
        """Test enhanced AI analyzer factory function."""
        from ai import create_enhanced_ai_analyzer
        
        analyzer = create_enhanced_ai_analyzer(api_key='enhanced-key')
        
        self.assertIsInstance(analyzer, EnhancedAIAnalyzer)
        self.assertEqual(analyzer.api_key, 'enhanced-key')


if __name__ == '__main__':
    unittest.main()