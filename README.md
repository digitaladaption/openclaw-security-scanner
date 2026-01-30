# 🛡️ OpenClaw Security Scanner

**Scan for security issues in OpenClaw/Clawdbot installations and report findings.**

Automatically gather security research from X, Reddit, Medium, and Moltbook - then scan your own bot for known vulnerabilities.

## 🎯 What It Does

- **Gathers intelligence** from social media and blogs about OpenClaw security issues
- **Scans your installation** for common vulnerabilities
- **Reports findings** with severity levels and remediation steps
- **Tracks emerging threats** in the community

## 📊 Data Sources

| Source | What It Finds |
|--------|---------------|
| **X/Twitter** | Real-time security discussions, vulnerability reports |
| **Reddit** | User-reported issues, security threads |
| **Medium** | In-depth security analysis articles |
| **Moltbook** | Agent community security discussions |
| **GitHub** | CVEs, issues, security advisories |

## 🔍 What It Scans

- **Skill.md files** - Malicious instructions, credential access
- **Exec permissions** - Unsafe command allowlisting
- **API keys** - Exposure risks, storage security
- **Network exposure** - Open ports, exposed services
- **Memory安全** - Session handling, data retention

## 🚀 Quick Start

```bash
# Install
git clone https://github.com/digitaladaption/openclaw-security-scanner.git
cd openclaw-security-scanner

# Run security scan
python3 scan.py --full

# Check for new threats
python3 monitor.py --sources x,reddit,moltbook

# Generate report
python3 report.py --format markdown
```

## 📋 Example Report

```
# OpenClaw Security Report
Generated: 2026-01-30 21:00 UTC

## Threats Found: 3

### High Severity
🔴 CVE-2026-XXX - Skill.md injection vulnerability
   - Affected: All installations
   - Fix: Update to latest version
   - Reference: https://moltbook.com/post/...

### Medium Severity
🟡 Exec allowlist misconfiguration
   - Affected: 30% of installations
   - Fix: Review exec-approvals.json
   - Reference: https://x.com/...

### Low Severity
🟢 Outdated dependencies
   - Fix: npm audit fix
```

## 🛠️ Scripts

| Script | Purpose |
|--------|---------|
| `scan.py` | Scan local OpenClaw installation |
| `monitor.py` | Track new security threats |
| `report.py` | Generate security reports |
| `intel.py` | Gather intelligence from sources |

## 📚 Data Sources

- Twitter/X search for #OpenClaw security issues
- Reddit r/LocalLLM security discussions
- Moltbook security posts
- GitHub security advisories

## 🤝 Contributing

Pull requests welcome! Especially for:
- New data sources
- Additional vulnerability checks
- Better remediation recommendations

## 📝 License

MIT License
