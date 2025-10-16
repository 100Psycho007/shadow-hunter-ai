"""
AI Integration Module for Threat Analysis

This module provides AI-powered threat analysis capabilities using the OpenRouter API.
It includes functionality for generating threat summaries, handling API errors,
and caching results to optimize performance.
"""

import os
import json
import time
import hashlib
from typing import Dict, List, Optional, Any
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class AIAnalyzer:
    """
    AI analyzer class for generating threat summaries using OpenRouter API.
    
    Handles API key validation, request formatting, error handling, and response caching.
    """
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        """
        Initialize the AI analyzer.
        
        Args:
            api_key: OpenRouter API key. If None, will check environment variable.
            timeout: Request timeout in seconds (default: 30)
        """
        self.api_key = api_key or self._get_api_key_from_env()
        self.timeout = timeout
        self.base_url = "https://openrouter.ai/api/v1"
        self.model = "anthropic/claude-3-haiku"  # Fast, cost-effective model for summaries
        self.cache = {}  # In-memory cache for AI summaries
        
        # Configure session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def _get_api_key_from_env(self) -> Optional[str]:
        """
        Get API key from environment variable.
        
        Returns:
            API key string or None if not found
        """
        return os.getenv('OPENROUTER_API_KEY')
    
    def is_enabled(self) -> bool:
        """
        Check if AI functionality is enabled (API key is available).
        
        Returns:
            True if API key is configured, False otherwise
        """
        return self.api_key is not None and len(self.api_key.strip()) > 0
    
    def validate_api_key(self) -> bool:
        """
        Validate the API key by making a test request.
        
        Returns:
            True if API key is valid, False otherwise
        """
        if not self.is_enabled():
            return False
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            # Make a minimal test request
            test_payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": "Test"}],
                "max_tokens": 1
            }
            
            response = self.session.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=test_payload,
                timeout=10
            )
            
            return response.status_code == 200
            
        except Exception:
            return False
    
    def _generate_cache_key(self, report: Dict[str, Any]) -> str:
        """
        Generate a cache key for a report to avoid duplicate API calls.
        
        Args:
            report: Report dictionary
            
        Returns:
            MD5 hash string to use as cache key
        """
        # Create a stable string representation of the report
        cache_data = {
            "target": report.get("target", ""),
            "scan_date": report.get("scan_date", ""),
            "subdomains": sorted(report.get("subdomains", [])),
            "open_ports": dict(sorted(report.get("open_ports", {}).items())),
            "vulnerabilities": report.get("vulnerabilities", [])
        }
        
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.md5(cache_string.encode()).hexdigest()
    
    def format_prompt(self, report: Dict[str, Any]) -> str:
        """
        Format report data into a prompt for AI analysis.
        
        Args:
            report: Report dictionary containing scan results
            
        Returns:
            Formatted prompt string for AI analysis
        """
        target = report.get("target", "Unknown")
        scan_date = report.get("scan_date", "Unknown")
        subdomains = report.get("subdomains", [])
        open_ports = report.get("open_ports", {})
        vulnerabilities = report.get("vulnerabilities", [])
        
        prompt = f"""Analyze this cybersecurity reconnaissance report and provide a threat assessment:

TARGET: {target}
SCAN DATE: {scan_date}

DISCOVERED SUBDOMAINS ({len(subdomains)}):
{', '.join(subdomains[:10])}{'...' if len(subdomains) > 10 else ''}

OPEN PORTS ({len(open_ports)}):
{', '.join([f"{port}({service})" for port, service in list(open_ports.items())[:10]])}{'...' if len(open_ports) > 10 else ''}

VULNERABILITIES FOUND ({len(vulnerabilities)}):
"""
        
        # Add vulnerability details
        for i, vuln in enumerate(vulnerabilities[:5]):  # Limit to first 5 vulnerabilities
            severity = vuln.get("severity", "unknown")
            title = vuln.get("title", "Unknown vulnerability")
            prompt += f"- {severity.upper()}: {title}\n"
        
        if len(vulnerabilities) > 5:
            prompt += f"... and {len(vulnerabilities) - 5} more vulnerabilities\n"
        
        prompt += """
Please provide:
1. RISK LEVEL (Low/Medium/High/Critical) with brief justification
2. KEY CONCERNS: Top 3 security issues to prioritize
3. ATTACK VECTORS: Potential ways an attacker could exploit these findings
4. RECOMMENDATIONS: Specific actions to improve security posture

Keep the response concise but actionable for a security analyst."""
        
        return prompt    

    def generate_summary(self, report: Dict[str, Any]) -> Optional[str]:
        """
        Generate AI threat summary for a report.
        
        Args:
            report: Report dictionary containing scan results
            
        Returns:
            AI-generated threat summary string, or None if generation fails
        """
        if not self.is_enabled():
            return None
        
        # Check cache first
        cache_key = self._generate_cache_key(report)
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/your-repo/ai-threat-hunting-dashboard",
                "X-Title": "AI Threat Hunting Dashboard"
            }
            
            prompt = self.format_prompt(report)
            
            payload = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert analyzing reconnaissance scan results. Provide clear, actionable threat assessments."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "max_tokens": 800,
                "temperature": 0.3,  # Lower temperature for more consistent analysis
                "top_p": 0.9
            }
            
            response = self.session.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                response_data = response.json()
                
                if "choices" in response_data and len(response_data["choices"]) > 0:
                    summary = response_data["choices"][0]["message"]["content"].strip()
                    
                    # Cache the result
                    self.cache[cache_key] = summary
                    
                    return summary
                else:
                    print(f"AI API Warning: Unexpected response format: {response_data}")
                    return None
            
            elif response.status_code == 401:
                print("AI API Error: Invalid API key")
                return None
            
            elif response.status_code == 429:
                print("AI API Error: Rate limit exceeded. Please try again later.")
                return None
            
            elif response.status_code == 402:
                print("AI API Error: Insufficient credits. Please check your OpenRouter account.")
                return None
            
            else:
                print(f"AI API Error: HTTP {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.Timeout:
            print(f"AI API Error: Request timed out after {self.timeout} seconds")
            return None
        
        except requests.exceptions.ConnectionError:
            print("AI API Error: Connection failed. Please check your internet connection.")
            return None
        
        except requests.exceptions.RequestException as e:
            print(f"AI API Error: Request failed - {str(e)}")
            return None
        
        except json.JSONDecodeError:
            print("AI API Error: Invalid JSON response")
            return None
        
        except Exception as e:
            print(f"AI API Error: Unexpected error - {str(e)}")
            return None
    
    def get_cached_summary(self, report: Dict[str, Any]) -> Optional[str]:
        """
        Get cached AI summary for a report without making API call.
        
        Args:
            report: Report dictionary
            
        Returns:
            Cached summary string or None if not cached
        """
        cache_key = self._generate_cache_key(report)
        return self.cache.get(cache_key)
    
    def clear_cache(self) -> None:
        """Clear all cached AI summaries."""
        self.cache.clear()
    
    def get_cache_stats(self) -> Dict[str, int]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        return {
            "cached_summaries": len(self.cache),
            "total_cache_size": sum(len(summary) for summary in self.cache.values())
        }


def check_api_key() -> Optional[str]:
    """
    Utility function to check for OpenRouter API key in environment.
    
    Returns:
        API key string or None if not found
    """
    return os.getenv('OPENROUTER_API_KEY')


def create_ai_analyzer(api_key: Optional[str] = None) -> AIAnalyzer:
    """
    Factory function to create an AIAnalyzer instance.
    
    Args:
        api_key: Optional API key. If None, will check environment variable.
        
    Returns:
        AIAnalyzer instance
    """
    return AIAnalyzer(api_key=api_key)


# Example usage and testing functions
if __name__ == "__main__":
    # Example usage
    analyzer = AIAnalyzer()
    
    if analyzer.is_enabled():
        print("AI functionality is enabled")
        
        # Test with sample report
        sample_report = {
            "target": "example.com",
            "scan_date": "2025-01-15",
            "subdomains": ["www.example.com", "api.example.com", "admin.example.com"],
            "open_ports": {"80": "http", "443": "https", "22": "ssh"},
            "vulnerabilities": [
                {
                    "severity": "high",
                    "title": "SSH with weak authentication",
                    "description": "SSH service allows password authentication",
                    "affected_service": "ssh"
                }
            ]
        }
        
        print("Generating AI summary...")
        summary = analyzer.generate_summary(sample_report)
        
        if summary:
            print("AI Summary:")
            print(summary)
        else:
            print("Failed to generate AI summary")
    else:
        print("AI functionality is disabled - no API key configured")
        print("Set OPENROUTER_API_KEY environment variable to enable AI features")


class ReportAICache:
    """
    Enhanced caching mechanism for AI summaries integrated with report data structure.
    
    This class provides persistent caching, cache invalidation, and integration
    with the report loading system.
    """
    
    def __init__(self, cache_file: Optional[str] = None):
        """
        Initialize the report AI cache.
        
        Args:
            cache_file: Optional path to persistent cache file
        """
        self.cache_file = cache_file or "ai_cache.json"
        self.memory_cache = {}
        self.load_persistent_cache()
    
    def load_persistent_cache(self) -> None:
        """Load cache from persistent storage if available."""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.memory_cache = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load AI cache from {self.cache_file}: {e}")
                self.memory_cache = {}
    
    def save_persistent_cache(self) -> None:
        """Save cache to persistent storage."""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.memory_cache, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save AI cache to {self.cache_file}: {e}")
    
    def get_cache_key(self, report: Dict[str, Any]) -> str:
        """
        Generate a cache key for a report.
        
        Args:
            report: Report dictionary
            
        Returns:
            Cache key string
        """
        # Create a stable representation of the report content
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
    
    def get_cached_summary(self, report: Dict[str, Any]) -> Optional[str]:
        """
        Get cached AI summary for a report.
        
        Args:
            report: Report dictionary
            
        Returns:
            Cached summary or None if not found
        """
        # First check if summary is already in the report
        if report.get("ai_summary"):
            return report["ai_summary"]
        
        # Then check memory cache
        cache_key = self.get_cache_key(report)
        cache_entry = self.memory_cache.get(cache_key)
        if cache_entry and isinstance(cache_entry, dict):
            return cache_entry.get("summary")
        return cache_entry
    
    def cache_summary(self, report: Dict[str, Any], summary: str) -> None:
        """
        Cache an AI summary for a report.
        
        Args:
            report: Report dictionary
            summary: AI-generated summary to cache
        """
        cache_key = self.get_cache_key(report)
        self.memory_cache[cache_key] = {
            "summary": summary,
            "timestamp": time.time(),
            "target": report.get("target", "unknown")
        }
        
        # Save to persistent storage
        self.save_persistent_cache()
    
    def invalidate_cache(self, report: Dict[str, Any]) -> bool:
        """
        Invalidate cached summary for a report.
        
        Args:
            report: Report dictionary
            
        Returns:
            True if cache entry was removed, False if not found
        """
        cache_key = self.get_cache_key(report)
        if cache_key in self.memory_cache:
            del self.memory_cache[cache_key]
            self.save_persistent_cache()
            return True
        return False
    
    def clear_cache(self) -> None:
        """Clear all cached summaries."""
        self.memory_cache.clear()
        self.save_persistent_cache()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        total_size = sum(len(entry["summary"]) for entry in self.memory_cache.values())
        oldest_timestamp = min((entry["timestamp"] for entry in self.memory_cache.values()), default=0)
        newest_timestamp = max((entry["timestamp"] for entry in self.memory_cache.values()), default=0)
        
        return {
            "cached_summaries": len(self.memory_cache),
            "total_cache_size": total_size,
            "oldest_entry": time.ctime(oldest_timestamp) if oldest_timestamp else "N/A",
            "newest_entry": time.ctime(newest_timestamp) if newest_timestamp else "N/A",
            "cache_file": self.cache_file
        }


class EnhancedAIAnalyzer(AIAnalyzer):
    """
    Enhanced AI analyzer with integrated caching and report data structure support.
    
    This class extends the base AIAnalyzer with better caching mechanisms,
    report integration, and cache invalidation handling.
    """
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 30, cache_file: Optional[str] = None):
        """
        Initialize the enhanced AI analyzer.
        
        Args:
            api_key: OpenRouter API key
            timeout: Request timeout in seconds
            cache_file: Path to persistent cache file
        """
        super().__init__(api_key, timeout)
        self.report_cache = ReportAICache(cache_file)
    
    def generate_summary_for_report(self, report: Dict[str, Any], force_refresh: bool = False) -> Optional[str]:
        """
        Generate or retrieve AI summary for a report with integrated caching.
        
        Args:
            report: Report dictionary
            force_refresh: If True, bypass cache and generate new summary
            
        Returns:
            AI summary string or None if generation fails
        """
        if not self.is_enabled():
            return None
        
        # Check cache first unless force refresh is requested
        if not force_refresh:
            cached_summary = self.report_cache.get_cached_summary(report)
            if cached_summary:
                return cached_summary
        
        # Generate new summary
        summary = self.generate_summary(report)
        
        if summary:
            # Cache the result
            self.report_cache.cache_summary(report, summary)
            
            # Also store in the report structure if it's a mutable dict
            if isinstance(report, dict):
                report["ai_summary"] = summary
        
        return summary
    
    def update_report_with_ai_summary(self, report: Dict[str, Any], force_refresh: bool = False) -> bool:
        """
        Update a report dictionary with AI summary.
        
        Args:
            report: Report dictionary to update
            force_refresh: If True, bypass cache and generate new summary
            
        Returns:
            True if summary was added/updated, False otherwise
        """
        summary = self.generate_summary_for_report(report, force_refresh)
        
        if summary:
            report["ai_summary"] = summary
            return True
        
        return False
    
    def batch_generate_summaries(self, reports: List[Dict[str, Any]], 
                                force_refresh: bool = False,
                                progress_callback: Optional[callable] = None) -> Dict[str, str]:
        """
        Generate AI summaries for multiple reports with progress tracking.
        
        Args:
            reports: List of report dictionaries
            force_refresh: If True, bypass cache for all reports
            progress_callback: Optional callback function for progress updates
            
        Returns:
            Dictionary mapping report targets to their AI summaries
        """
        results = {}
        
        for i, report in enumerate(reports):
            target = report.get("target", f"report_{i}")
            
            if progress_callback:
                progress_callback(i, len(reports), target)
            
            summary = self.generate_summary_for_report(report, force_refresh)
            if summary:
                results[target] = summary
            
            # Small delay to avoid overwhelming the API
            time.sleep(0.1)
        
        return results
    
    def invalidate_report_cache(self, report: Dict[str, Any]) -> bool:
        """
        Invalidate cached summary for a specific report.
        
        Args:
            report: Report dictionary
            
        Returns:
            True if cache was invalidated, False if not found
        """
        # Remove from report structure
        if "ai_summary" in report:
            del report["ai_summary"]
        
        # Remove from cache
        return self.report_cache.invalidate_cache(report)
    
    def get_enhanced_cache_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive cache statistics.
        
        Returns:
            Dictionary with detailed cache statistics
        """
        base_stats = self.get_cache_stats()
        report_stats = self.report_cache.get_cache_stats()
        
        return {
            "memory_cache": base_stats,
            "persistent_cache": report_stats,
            "total_cached_summaries": base_stats["cached_summaries"] + report_stats["cached_summaries"]
        }


def create_enhanced_ai_analyzer(api_key: Optional[str] = None, 
                              cache_file: Optional[str] = None) -> EnhancedAIAnalyzer:
    """
    Factory function to create an EnhancedAIAnalyzer instance.
    
    Args:
        api_key: Optional API key
        cache_file: Optional path to persistent cache file
        
    Returns:
        EnhancedAIAnalyzer instance
    """
    return EnhancedAIAnalyzer(api_key=api_key, cache_file=cache_file)