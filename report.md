# 🔒 OpenClaw Security Report
Generated: 2026-01-30T21:17:05.183040

## Executive Summary
- **Total Issues Found:** 22
- **High Severity:** 🔴 15
- **Medium Severity:** 🟡 0
- **Low Severity:** 🟢 7

## Severity Breakdown

### Critical Findings (15)
1. **credential_exposure**
   - Location: /root/.clawdbot/clawdbot.json
   - Issue: Potential credential found: "token": "***
   - Fix: Move credentials to environment variables or secure vault
2. **credential_exposure**
   - Location: /root/.clawdbot/exec-approvals.json
   - Issue: Potential credential found: "token": "***
   - Fix: Move credentials to environment variables or secure vault
3. **credential_exposure**
   - Location: /root/.clawdbot/exec-approvals.json
   - Issue: Potential credential found: Bearer mol***
   - Fix: Move credentials to environment variables or secure vault
4. **credential_exposure**
   - Location: /root/.clawdbot/identity/device-auth.json
   - Issue: Potential credential found: "token": "***
   - Fix: Move credentials to environment variables or secure vault
5. **credential_exposure**
   - Location: /root/.clawdbot/devices/paired.json
   - Issue: Potential credential found: "token": "***
   - Fix: Move credentials to environment variables or secure vault
6. **credential_exposure**
   - Location: /root/.clawdbot/agents/main/agent/auth-profiles.json
   - Issue: Potential credential found: "api_key":***
   - Fix: Move credentials to environment variables or secure vault
7. **injection_pattern**
   - Location: /root/clawd/skills/health-analytics/SKILL.md
   - Issue: Potential command substitution in markdown
   - Fix: Review and sanitize input handling
8. **injection_pattern**
   - Location: /root/clawd/skills/cron-helper/SKILL.md
   - Issue: Potential command substitution in markdown
   - Fix: Review and sanitize input handling
9. **injection_pattern**
   - Location: /root/clawd/skills/cron-creator/SKILL.md
   - Issue: Potential shell variable expansion in markdown
   - Fix: Review and sanitize input handling
10. **injection_pattern**
   - Location: /root/clawd/skills/model-router/SKILL.md
   - Issue: Potential command substitution in markdown
   - Fix: Review and sanitize input handling
11. **injection_pattern**
   - Location: /root/clawd/skills/model-router/references/USAGE_EXAMPLES.md
   - Issue: Potential command substitution in markdown
   - Fix: Review and sanitize input handling
12. **injection_pattern**
   - Location: /root/clawd/skills/model-router/references/model-specs.md
   - Issue: Potential command substitution in markdown
   - Fix: Review and sanitize input handling
13. **injection_pattern**
   - Location: /root/clawd/skills/cron-helper/references/TROUBLESHOOTING.md
   - Issue: Potential command substitution in markdown
   - Fix: Review and sanitize input handling
14. **injection_pattern**
   - Location: /root/clawd/skills/cron-helper/references/SCHEMA.md
   - Issue: Potential command substitution in markdown
   - Fix: Review and sanitize input handling
15. **injection_pattern**
   - Location: /root/clawd/skills/cron-helper/references/EXAMPLES.md
   - Issue: Potential command substitution in markdown
   - Fix: Review and sanitize input handling

### Medium Severity Issues (0)
No medium severity issues found.

### Low Severity Notes (7)
1. **open_port**
   - Location: 22
   - Issue: Port 22 (SSH) is open on localhost
   - Fix: Ensure only necessary ports are exposed
2. **open_port**
   - Location: 80
   - Issue: Port 80 (HTTP) is open on localhost
   - Fix: Ensure only necessary ports are exposed
3. **open_port**
   - Location: 443
   - Issue: Port 443 (HTTPS) is open on localhost
   - Fix: Ensure only necessary ports are exposed
4. **open_port**
   - Location: 3306
   - Issue: Port 3306 (MySQL) is open on localhost
   - Fix: Ensure only necessary ports are exposed
5. **open_port**
   - Location: 5432
   - Issue: Port 5432 (PostgreSQL) is open on localhost
   - Fix: Ensure only necessary ports are exposed
6. **open_port**
   - Location: 6379
   - Issue: Port 6379 (Redis) is open on localhost
   - Fix: Ensure only necessary ports are exposed
7. **open_port**
   - Location: 8000
   - Issue: Port 8000 (Dev-HTTP) is open on localhost
   - Fix: Ensure only necessary ports are exposed

## Affected Components
- credential_exposure
- open_port
- injection_pattern

## Remediation Steps
- Ensure only necessary ports are exposed
- Move credentials to environment variables or secure vault
- Review and sanitize input handling

## Intelligence Sources
- [X](https://x.com/example/status/123): Sample finding for OpenClaw security...
- [X](https://x.com/example/status/123): Sample finding for Clawdbot vulnerability...
- [Reddit](https://reddit.com/r/example/comments/123): Reddit discussion about LocalLLM security...
- [Reddit](https://reddit.com/r/example/comments/123): Reddit discussion about OpenClaw hack...
- [Moltbook](https://moltbook.com/example): Moltbook post about security...
- [Moltbook](https://moltbook.com/example): Moltbook post about vulnerability...

---
*Report generated by OpenClaw Security Scanner*
