# MITRE ATT&CK Technique Reference

This document maps the detection rules in this project to MITRE ATT&CK techniques.

## Techniques Detected

### T1110.001 — Brute Force: Password Guessing
- **Tactic:** Credential Access
- **Detection Rule:** Rule 001 — SSH Brute Force
- **Trigger:** >5 failed SSH auth attempts from same IP within monitoring window
- **Mitigation:** M1036 (Account Use Policies), M1032 (Multi-factor Authentication)

### T1046 — Network Service Discovery
- **Tactic:** Discovery
- **Detection Rule:** Rule 002 — Port Scan Detection
- **Trigger:** >6 unique ports scanned from same external IP
- **Mitigation:** M1030 (Network Segmentation), M1031 (Network Intrusion Prevention)

### T1071.004 — Application Layer Protocol: DNS
- **Tactic:** Command and Control
- **Detection Rule:** Rule 003 — DNS Anomaly / Tunneling
- **Trigger:** Long subdomains (>30 chars) + TXT record queries = tunneling indicator
- **Mitigation:** M1031 (Network Intrusion Prevention), M1037 (Filter Network Traffic)

### T1136.001 — Create Account: Local Account
- **Tactic:** Persistence
- **Detection Rule:** Rule 004 — New User Account Creation
- **Trigger:** useradd event detected in system logs
- **Mitigation:** M1032 (Multi-factor Authentication), M1026 (Privileged Account Management)

### T1548.003 — Abuse Elevation Control Mechanism: Sudo
- **Tactic:** Privilege Escalation
- **Detection Rule:** Rule 005 — Suspicious Sudo Commands
- **Trigger:** sudo commands containing: /etc/shadow, nc, netcat, wget, chmod 777, base64
- **Mitigation:** M1026 (Privileged Account Management), M1038 (Execution Prevention)

### T1071.001 — Application Layer Protocol: Web Protocols
- **Tactic:** Command and Control
- **Detection Rule:** Rule 006 — Known Malicious IP Communication
- **Trigger:** Any traffic involving IPs from threat intelligence feeds
- **Mitigation:** M1031 (Network Intrusion Prevention), M1037 (Filter Network Traffic)

### T1041 — Exfiltration Over C2 Channel
- **Tactic:** Exfiltration
- **Detection Rule:** Rule 007 — C2 Beaconing Pattern
- **Trigger:** >3 periodic connections to same external IP = beaconing
- **Mitigation:** M1031 (Network Intrusion Prevention), M1057 (Data Loss Prevention)

## Detection Logic Summary

```
Rule 001: count(failed_ssh[src_ip]) > 5  →  HIGH
Rule 002: count(distinct_ports[src_ip]) > 6  →  MEDIUM
Rule 003: count(long_dns_subdomains[src_ip]) > 3  →  HIGH
Rule 004: event_type == "useradd"  →  HIGH
Rule 005: sudo_command contains [shadow|nc|netcat|wget|chmod 777]  →  CRITICAL
Rule 006: ip in threat_intel_feed  →  CRITICAL
Rule 007: count(outbound[src][dst]) > 3 && dst in threat_intel  →  CRITICAL
```
