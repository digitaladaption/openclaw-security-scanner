#!/usr/bin/env python3
"""
Security Scanner for OpenClaw/Clawdbot
Scans for common security issues and outputs severity levels.
"""

import json
import os
import re
import socket
from pathlib import Path
from typing import Dict, List, Tuple

class SecurityScanner:
    def __init__(self):
        self.issues = []
        
    def scan_exec_approvals(self) -> List[Dict]:
        """Scan exec-approvals.json for full path issues."""
        issues = []
        config_path = Path.home() / ".clawdbot" / "exec-approvals.json"
        
        if not config_path.exists():
            return issues
            
        try:
            with open(config_path) as f:
                data = json.load(f)
                
            if isinstance(data, dict) and 'approvals' in data:
                for item in data['approvals']:
                    command = item.get('command', '')
                    # Check for missing full path
                    if command and not command.startswith('/'):
                        issues.append({
                            'type': 'full_path',
                            'severity': 'Medium',
                            'file': str(config_path),
                            'issue': f"Command without full path: {command}",
                            'remediation': "Use absolute paths (e.g., /usr/bin/python instead of python)"
                        })
        except Exception as e:
            issues.append({
                'type': 'parse_error',
                'severity': 'Low',
                'file': str(config_path),
                'issue': f"Failed to parse config: {str(e)}",
                'remediation': "Check JSON syntax"
            })
            
        return issues
    
    def scan_credentials_exposure(self) -> List[Dict]:
        """Check ~/.clawdbot/ for exposed credentials."""
        issues = []
        clawdbot_dir = Path.home() / ".clawdbot"
        
        if not clawdbot_dir.exists():
            return issues
            
        # Patterns for common credential formats
        credential_patterns = [
            (r'["\']?(?:api[_-]?key|apikey|secret|token|password)["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{20,}["\']?', 'High'),
            (r'Bearer\s+[a-zA-Z0-9_\-\.]+', 'High'),
            (r'ghp_[a-zA-Z0-9]{36}', 'High'),
            (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*', 'High'),
        ]
        
        for file_path in clawdbot_dir.rglob('*.json'):
            if 'credentials' in str(file_path).lower():
                continue  # Skip the credentials directory itself
                
            try:
                with open(file_path) as f:
                    content = f.read()
                    
                for pattern, severity in credential_patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        for match in matches:
                            masked = match[:10] + '***' if len(match) > 10 else '***'
                            issues.append({
                                'type': 'credential_exposure',
                                'severity': severity,
                                'file': str(file_path),
                                'issue': f"Potential credential found: {masked}",
                                'remediation': "Move credentials to environment variables or secure vault"
                            })
            except Exception:
                pass
                
        return issues
    
    def scan_injection_patterns(self) -> List[Dict]:
        """Validate skill/*.md for injection patterns."""
        issues = []
        skills_dir = Path("/root/clawd/skills")
        
        if not skills_dir.exists():
            # Try relative to home
            skills_dir = Path.home() / "skills"
            
        if not skills_dir.exists():
            return issues
            
        # Dangerous patterns that could lead to injection
        injection_patterns = [
            (r'\$[{(\[]', 'High', 'Shell variable expansion'),
            (r'`[^`]+`', 'High', 'Command substitution'),
            (r'\|\s*sh\b', 'High', 'Pipe to shell'),
            (r';[ \t]*(?:rm|cat|chmod|wget|curl)', 'High', 'Shell command injection'),
            (r'\bsudo\b', 'Medium', 'Sudo usage detected'),
        ]
        
        for md_file in skills_dir.rglob('*.md'):
            try:
                with open(md_file) as f:
                    content = f.read()
                    
                for pattern, severity, desc in injection_patterns:
                    if re.search(pattern, content):
                        issues.append({
                            'type': 'injection_pattern',
                            'severity': severity,
                            'file': str(md_file),
                            'issue': f"Potential {desc.lower()} in markdown",
                            'remediation': "Review and sanitize input handling"
                        })
                        break  # One issue per file is enough
            except Exception:
                pass
                
        return issues
    
    def scan_network_ports(self) -> List[Dict]:
        """Check for open network ports."""
        issues = []
        common_ports = [22, 80, 443, 8080, 8443, 3306, 5432, 6379, 8000, 9000]
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:
                service = self._get_port_service(port)
                issues.append({
                    'type': 'open_port',
                    'severity': 'Low',
                    'port': port,
                    'service': service,
                    'issue': f"Port {port} ({service}) is open on localhost",
                    'remediation': "Ensure only necessary ports are exposed"
                })
                
        return issues
    
    def _get_port_service(self, port: int) -> str:
        """Map common ports to service names."""
        services = {
            22: 'SSH', 80: 'HTTP', 443: 'HTTPS',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            3306: 'MySQL', 5432: 'PostgreSQL',
            6379: 'Redis', 8000: 'Dev-HTTP', 9000: 'Dev-HTTP'
        }
        return services.get(port, 'Unknown')
    
    def run_scan(self) -> Dict:
        """Run all security scans and return results."""
        self.issues = []
        
        self.issues.extend(self.scan_exec_approvals())
        self.issues.extend(self.scan_credentials_exposure())
        self.issues.extend(self.scan_injection_patterns())
        self.issues.extend(self.scan_network_ports())
        
        # Count by severity
        severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
        for issue in self.issues:
            severity_counts[issue['severity']] += 1
            
        return {
            'summary': severity_counts,
            'issues': self.issues,
            'total_issues': len(self.issues)
        }

if __name__ == '__main__':
    scanner = SecurityScanner()
    results = scanner.run_scan()
    
    print("\n" + "="*60)
    print("🔒 OpenClaw Security Scan Results")
    print("="*60)
    print(f"\nTotal Issues: {results['total_issues']}")
    print(f"  🔴 High:   {results['summary']['High']}")
    print(f"  🟡 Medium: {results['summary']['Medium']}")
    print(f"  🟢 Low:    {results['summary']['Low']}")
    
    if results['issues']:
        print("\n--- Detailed Findings ---")
        for i, issue in enumerate(results['issues'], 1):
            print(f"\n{i}. [{issue['severity']}] {issue['type']}")
            print(f"   File/Port: {issue.get('file', issue.get('port', 'N/A'))}")
            print(f"   Issue: {issue['issue']}")
            print(f"   Fix: {issue['remediation']}")
    
    print("\n" + "="*60)
