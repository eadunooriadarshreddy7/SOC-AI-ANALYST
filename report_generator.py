"""
report_generator.py

Auto-generates incident response reports from triage results.

The report format follows NIST SP 800-61 (the incident handling guide).
I read through that document a few times while building this — it's actually
really useful for understanding what goes into a proper IR report.

Reports get saved as markdown files. Could export to PDF with a converter
but markdown is fine for now and easy to read on GitHub.

I wanted the reports to look professional enough that I could actually show
them to someone as an example of incident documentation. The AI triage
output feeds directly into the report so the analyst notes and recommended
actions are automatically included.

One thing I noticed: the reports were really long at first. Trimmed them down
to include only the key info a reviewer would actually want to see quickly.
"""

import json
import os
from datetime import datetime


SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "⚪",
}

VERDICT_EMOJI = {
    "TRUE_POSITIVE": "✅",
    "FALSE_POSITIVE": "❌",
    "NEEDS_INVESTIGATION": "🔍",
}


def generate_executive_summary(alerts: list) -> str:
    total = len(alerts)
    critical = sum(1 for a in alerts if a.get("ai_analysis", {}).get("confirmed_severity") == "CRITICAL")
    high = sum(1 for a in alerts if a.get("ai_analysis", {}).get("confirmed_severity") == "HIGH")
    tp = sum(1 for a in alerts if a.get("ai_analysis", {}).get("verdict") == "TRUE_POSITIVE")
    escalate = sum(1 for a in alerts if a.get("ai_analysis", {}).get("escalate"))
    
    threat_ips = list(set(a.get("src_ip", "") for a in alerts if a.get("threat_intel", {}).get("known_attacker")))
    
    return f"""## Executive Summary

During the monitoring period, **{total} security alerts** were detected and triaged on the home network. 
AI-powered analysis confirmed **{tp} true positive incidents**, including **{critical} critical** and **{high} high severity** events. 
**{escalate} incidents** require immediate escalation and response.

Threat actors from **{len(threat_ips)} known-malicious IP addresses** were identified interacting with internal systems. 
Attack types include SSH brute force, port scanning, DNS tunneling, privilege escalation, and possible C2 communication.

**Immediate action is required** to contain the identified threats and prevent further compromise."""


def format_alert_section(alert: dict, index: int) -> str:
    ai = alert.get("ai_analysis", {})
    intel = alert.get("threat_intel", {})
    
    sev = ai.get("confirmed_severity", alert.get("severity", "UNKNOWN"))
    verdict = ai.get("verdict", "UNKNOWN")
    sev_emoji = SEVERITY_EMOJI.get(sev, "⚪")
    verdict_emoji = VERDICT_EMOJI.get(verdict, "❓")
    
    actions = "\n".join(f"   {i+1}. {a}" for i, a in enumerate(ai.get("immediate_actions", [])))
    
    intel_section = ""
    if intel:
        intel_section = f"""
**Threat Intelligence:**
- Abuse Score: **{intel.get('abuse_score', 'N/A')}/100**
- Reports: {intel.get('reports', 0)} threat reports
- Country: {intel.get('country', 'Unknown')} | ISP: {intel.get('isp', 'Unknown')}
- Tags: {', '.join(f'`{t}`' for t in intel.get('tags', [])[:4]) or 'None'}
"""
    
    escalation_text = ""
    if ai.get("escalate"):
        escalation_text = f"\n> ⚠️ **ESCALATION REQUIRED:** {ai.get('escalation_reason', '')}\n"
    
    return f"""---

### Alert {index}: {alert.get('rule_name', 'Unknown Alert')}

| Field | Value |
|-------|-------|
| **Alert ID** | `{alert.get('alert_id', 'N/A')}` |
| **Severity** | {sev_emoji} {sev} |
| **Verdict** | {verdict_emoji} {verdict} |
| **Confidence** | {ai.get('confidence', 0)}% |
| **MITRE ATT&CK** | `{ai.get('mitre_technique', {}).get('tid', alert.get('mitre_tid', 'N/A'))}` — {ai.get('mitre_technique', {}).get('name', alert.get('mitre_name', 'N/A'))} |
| **Tactic** | {ai.get('mitre_technique', {}).get('tactic', 'N/A')} |
| **Source IP** | `{alert.get('src_ip', 'N/A')}` |
| **Detection Time** | {alert.get('timestamp', 'N/A')} |

**Description:** {alert.get('description', 'N/A')}
{intel_section}
**AI Analysis:**
> {ai.get('attack_summary', 'No analysis available')}
{escalation_text}
**Immediate Response Actions:**
{actions}

**Analyst Notes:** {ai.get('analyst_notes', 'None')}

**Sample Evidence:**
```
{alert.get('sample_log', 'No log available')}
```
"""


def generate_ioc_section(alerts: list) -> str:
    ips = {}
    for alert in alerts:
        ip = alert.get("src_ip", "")
        intel = alert.get("threat_intel", {})
        if ip and intel:
            ips[ip] = intel
    
    if not ips:
        return ""
    
    rows = []
    for ip, intel in ips.items():
        score = intel.get("abuse_score", 0)
        score_display = f"🔴 {score}" if score > 70 else f"🟡 {score}" if score > 30 else f"🟢 {score}"
        rows.append(f"| `{ip}` | {score_display}/100 | {intel.get('country', 'N/A')} | {', '.join(intel.get('categories', [])[:2])} | {'⚠️ Yes' if intel.get('known_attacker') else 'No'} |")
    
    table = "\n".join(rows)
    
    return f"""---

## Indicators of Compromise (IOCs)

### Malicious IP Addresses

| IP Address | Abuse Score | Country | Categories | Known Threat Actor |
|-----------|-------------|---------|------------|-------------------|
{table}

> These IPs should be **immediately blocked** at the perimeter firewall and added to your threat intelligence platform.
"""


def generate_recommendations_section() -> str:
    return """---

## Recommendations

### Immediate Actions (0-24 hours)
1. **Block all identified threat actor IPs** at the perimeter firewall
2. **Isolate any hosts** showing C2 beaconing or DNS tunneling activity
3. **Force password resets** for all accounts targeted by brute force
4. **Disable password-based SSH** — enforce key-only authentication
5. **Audit all user accounts** — remove any unauthorized accounts created

### Short-term Hardening (1-7 days)
1. **Deploy fail2ban** to auto-block brute force sources
2. **Enable multi-factor authentication** on all remote access
3. **Restrict outbound DNS** to internal resolver only (prevents DNS tunneling)
4. **Implement network segmentation** — separate IoT from servers
5. **Enable logging** on all critical services (sshd, sudo, useradd, cron)

### Long-term Security Posture (1-30 days)
1. **Deploy an IDS/IPS** (Suricata or Snort) for real-time detection
2. **Set up centralized logging** (ELK stack or Graylog) for SIEM capabilities
3. **Conduct regular threat hunting** using this pipeline
4. **Subscribe to threat intelligence feeds** (AbuseIPDB, AlienVault OTX)
5. **Establish incident response playbooks** for each alert type detected

### MITRE ATT&CK Mitigations
| Technique | Mitigation |
|-----------|-----------|
| T1110.001 (Brute Force) | M1036 — Account Use Policies, M1032 — MFA |
| T1046 (Port Scan) | M1030 — Network Segmentation, M1031 — Network Intrusion Prevention |
| T1071.004 (DNS Tunnel) | M1031 — Network Intrusion Prevention, M1037 — Filter Network Traffic |
| T1136.001 (Create Account) | M1032 — MFA, M1026 — Privileged Account Management |
| T1548.003 (Sudo Abuse) | M1026 — Privileged Account Management, M1038 — Execution Prevention |
"""


def generate_full_report(alerts: list) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_str = datetime.now().strftime("%Y-%m-%d")
    
    # Stats
    total = len(alerts)
    tp = sum(1 for a in alerts if a.get("ai_analysis", {}).get("verdict") == "TRUE_POSITIVE")
    
    report = f"""# Security Incident Report
## Home Network SOC Analysis — AI-Assisted Triage

**Report ID:** IR-{datetime.now().strftime('%Y%m%d')}-001  
**Generated:** {now}  
**Analyst:** AI-Augmented SOC Pipeline  
**Classification:** CONFIDENTIAL  
**Status:** ACTIVE INCIDENT  

---

{generate_executive_summary(alerts)}

---

## Incident Statistics

| Metric | Count |
|--------|-------|
| Total Alerts Analyzed | {total} |
| True Positives | {tp} |
| False Positives | {total - tp} |
| Critical Severity | {sum(1 for a in alerts if a.get('ai_analysis', {}).get('confirmed_severity') == 'CRITICAL')} |
| High Severity | {sum(1 for a in alerts if a.get('ai_analysis', {}).get('confirmed_severity') == 'HIGH')} |
| Alerts Requiring Escalation | {sum(1 for a in alerts if a.get('ai_analysis', {}).get('escalate'))} |

---

## Detailed Alert Analysis

"""
    
    for i, alert in enumerate(alerts, 1):
        if alert.get("ai_analysis", {}).get("verdict") != "FALSE_POSITIVE":
            report += format_alert_section(alert, i)
    
    report += generate_ioc_section(alerts)
    report += generate_recommendations_section()
    
    report += f"""---

## Appendix: Detection Rules Triggered

| Rule ID | Rule Name | MITRE TID | Alerts |
|---------|-----------|-----------|--------|
"""
    
    seen_rules = {}
    for alert in alerts:
        rid = alert.get("rule_id", "N/A")
        if rid not in seen_rules:
            seen_rules[rid] = {
                "name": alert.get("rule_name", "Unknown"),
                "tid": alert.get("mitre_tid", "N/A"),
                "count": 0
            }
        seen_rules[rid]["count"] += 1
    
    for rid, info in sorted(seen_rules.items()):
        report += f"| {rid} | {info['name']} | `{info['tid']}` | {info['count']} |\n"
    
    report += f"""
---

*Report generated by AI-Powered SOC Analyst Pipeline*  
*AI Engine: Claude (Anthropic) | Detection: Custom SIEM Rules | Framework: MITRE ATT&CK*  
*[GitHub: github.com/yourusername/soc-ai-analyst](https://github.com/yourusername/soc-ai-analyst)*
"""
    
    return report


def run_report_generator():
    # Try triage results first, fall back to alerts
    try:
        with open("logs/triage_results.json") as f:
            alerts = json.load(f)
        print("[*] Loaded AI triage results")
    except FileNotFoundError:
        try:
            with open("logs/enriched_alerts.json") as f:
                alerts = json.load(f)
            print("[*] Loaded enriched alerts (no AI triage)")
        except FileNotFoundError:
            with open("logs/alerts.json") as f:
                alerts = json.load(f)
            print("[*] Loaded raw alerts")
    
    print("\n[*] Generating Incident Response Report...")
    
    report = generate_full_report(alerts)
    
    os.makedirs("reports", exist_ok=True)
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/IR_Report_{date_str}.md"
    
    with open(filename, "w") as f:
        f.write(report)
    
    # Also save as latest
    with open("reports/latest_report.md", "w") as f:
        f.write(report)
    
    print(f"[+] Report saved to {filename}")
    print(f"[+] Latest report: reports/latest_report.md")
    print(f"\n[*] Report stats:")
    print(f"    Lines: {len(report.splitlines())}")
    print(f"    Size: {len(report)} characters")
    
    return report


if __name__ == "__main__":
    run_report_generator()
