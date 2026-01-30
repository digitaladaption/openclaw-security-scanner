#!/usr/bin/env python3
"""
Security Threat Monitor
Tracks emerging threats and alerts on high-severity issues.
"""

import json
import os
from datetime import datetime
from typing import Dict, List
from pathlib import Path

class ThreatMonitor:
    def __init__(self, state_file: str = "/tmp/openclaw-security-scanner/monitor_state.json"):
        self.state_file = state_file
        self.state = self._load_state()
    
    def _load_state(self) -> Dict:
        """Load previous state."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file) as f:
                    return json.load(f)
            except:
                pass
        return {
            'last_check': None,
            'known_threats': [],
            'alerts': []
        }
    
    def _save_state(self):
        """Save current state."""
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)
    
    def check_for_threats(self, intel_data: Dict) -> List[Dict]:
        """Check intel data for new high-severity threats."""
        new_alerts = []
        
        for cve in intel_data.get('cves', []):
            severity = cve.get('severity', 'Medium')
            if severity == 'High':
                # Check if already known
                known_ids = [t.get('cve_id') for t in self.state.get('known_threats', [])]
                if cve['cve_id'] not in known_ids:
                    alert = {
                        'type': 'new_cve',
                        'severity': 'High',
                        'cve_id': cve['cve_id'],
                        'description': cve['description'],
                        'detected_at': datetime.now().isoformat()
                    }
                    new_alerts.append(alert)
                    self.state['known_threats'].append(alert)
        
        self.state['last_check'] = datetime.now().isoformat()
        self._save_state()
        
        return new_alerts
    
    def alert_console(self, alerts: List[Dict]):
        """Output alerts to console."""
        print("\n" + "="*60)
        print("🚨 SECURITY ALERTS")
        print("="*60)
        
        if not alerts:
            print("✅ No new high-severity threats detected.")
        else:
            for alert in alerts:
                print(f"\n⚠️  [{alert['severity']}] {alert['cve_id']}")
                print(f"   {alert['description']}")
                print(f"   Detected: {alert['detected_at']}")
        
        print("\n" + "="*60)
    
    def save_alerts(self, alerts: List[Dict], filepath: str = "/tmp/openclaw-security-scanner/alerts.json"):
        """Save alerts to file."""
        output = {
            'generated': datetime.now().isoformat(),
            'alerts': alerts
        }
        
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"💾 Alerts saved to {filepath}")
        return filepath

if __name__ == '__main__':
    # Demo
    sample_intel = {
        'cves': [
            {
                'cve_id': 'CVE-2024-1234',
                'description': 'Remote code execution in OpenClaw',
                'severity': 'High'
            },
            {
                'cve_id': 'CVE-2024-5678',
                'description': 'Minor information disclosure',
                'severity': 'Low'
            }
        ]
    }
    
    monitor = ThreatMonitor()
    new_alerts = monitor.check_for_threats(sample_intel)
    monitor.alert_console(new_alerts)
    monitor.save_alerts(new_alerts)
