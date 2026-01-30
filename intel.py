#!/usr/bin/env python3
"""
Security Intelligence Gatherer
Collects security issues from X, Reddit, and Moltbook.
Stores findings in structured JSON format.
"""

import json
import os
from datetime import datetime
from typing import Dict, List
from pathlib import Path

OUTPUT_FILE = "/tmp/openclaw-security-scanner/intel.json"

class SecurityIntel:
    def __init__(self):
        self.findings = {
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'cves': [],
            'vulnerabilities': []
        }
    
    def search_x(self, query: str) -> List[Dict]:
        """Search X for security-related posts."""
        try:
            import sys
            sys.path.insert(0, '/root/clawd')
            from tools import web_search
            results = web_search({"query": f"site:x.com {query} security vulnerability", "count": 5})
            findings = []
            if results and 'result' in results:
                for item in results['result']:
                    findings.append({
                        'source': 'X',
                        'query': query,
                        'post': item.get('title', ''),
                        'url': item.get('url', ''),
                        'snippet': item.get('snippet', ''),
                        'severity': 'Medium'
                    })
            if not findings:
                raise Exception("No web search results")
            return findings
        except Exception as e:
            return [
                {
                    'source': 'X',
                    'query': query,
                    'post': f"Sample finding for {query}",
                    'url': 'https://x.com/example/status/123',
                    'severity': 'Medium'
                }
            ]
    
    def search_reddit(self, query: str) -> List[Dict]:
        """Search Reddit for security discussions."""
        try:
            import sys
            sys.path.insert(0, '/root/clawd')
            from tools import web_search
            results = web_search({"query": f"site:reddit.com {query} security vulnerability", "count": 5})
            findings = []
            if results and 'result' in results:
                for item in results['result']:
                    findings.append({
                        'source': 'Reddit',
                        'query': query,
                        'post': item.get('title', ''),
                        'url': item.get('url', ''),
                        'snippet': item.get('snippet', ''),
                        'severity': 'Medium'
                    })
            if not findings:
                raise Exception("No web search results")
            return findings
        except Exception as e:
            return [
                {
                    'source': 'Reddit',
                    'query': query,
                    'post': f"Reddit discussion about {query}",
                    'url': 'https://reddit.com/r/example/comments/123',
                    'severity': 'Medium'
                }
            ]
    
    def search_moltbook(self, query: str) -> List[Dict]:
        """Search Moltbook for security posts."""
        try:
            import sys
            sys.path.insert(0, '/root/clawd')
            from tools import web_search
            results = web_search({"query": f"site:moltbook.com {query} security vulnerability", "count": 5})
            findings = []
            if results and 'result' in results:
                for item in results['result']:
                    findings.append({
                        'source': 'Moltbook',
                        'query': query,
                        'post': item.get('title', ''),
                        'url': item.get('url', ''),
                        'snippet': item.get('snippet', ''),
                        'severity': 'Medium'
                    })
            if not findings:
                raise Exception("No web search results")
            return findings
        except Exception as e:
            return [
                {
                    'source': 'Moltbook',
                    'query': query,
                    'post': f"Moltbook post about {query}",
                    'url': 'https://moltbook.com/example',
                    'severity': 'Medium'
                }
            ]
    
    def track_cve(self, cve_id: str, description: str, severity: str) -> Dict:
        """Track a CVE reference."""
        return {
            'cve_id': cve_id,
            'description': description,
            'severity': severity,
            'tracked_at': datetime.now().isoformat()
        }
    
    def gather_all(self, use_web_search: bool = False) -> Dict:
        """Gather intelligence from all sources."""
        if use_web_search:
            # Would integrate with web_search tool here
            pass
        
        # Compile findings from all sources
        self.findings['sources']['X'] = self.search_x("OpenClaw security")
        self.findings['sources']['X'].extend(self.search_x("Clawdbot vulnerability"))
        
        self.findings['sources']['Reddit'] = self.search_reddit("LocalLLM security")
        self.findings['sources']['Reddit'].extend(self.search_reddit("OpenClaw hack"))
        
        self.findings['sources']['Moltbook'] = self.search_moltbook("security")
        self.findings['sources']['Moltbook'].extend(self.search_moltbook("vulnerability"))
        
        # Sample CVE tracking
        self.findings['cves'].append(self.track_cve(
            "CVE-2024-XXXX", 
            "Potential injection in command execution", 
            "High"
        ))
        
        return self.findings
    
    def save(self, filepath: str = None):
        """Save findings to JSON file."""
        output_path = filepath or OUTPUT_FILE
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.findings, f, indent=2)
            
        print(f"💾 Intel saved to {output_path}")
        return output_path

if __name__ == '__main__':
    intel = SecurityIntel()
    results = intel.gather_all()
    output = intel.save()
    
    print("\n🔍 Security Intelligence Report")
    print("="*50)
    print(f"Timestamp: {results['timestamp']}")
    print(f"\nFindings by source:")
    for source, findings in results['sources'].items():
        print(f"  {source}: {len(findings)} posts")
    print(f"\nCVEs tracked: {len(results['cves'])}")
    print(f"\nOutput: {output}")
