# SOC Analyst Home Lab — AI-Assisted Threat Detection

I built this project to practice what SOC Tier 2 analysts actually do at work, but from my home network. Been studying for my Security+ and kept reading about SIEM triage, MITRE ATT&CK, and incident response, but couldn't really *do* any of it without access to a real SOC environment. So I built one.

The idea was simple: capture my home network traffic, write detection rules like a SIEM would, and when something suspicious pops up — use an AI model to triage it the way a Tier 2 analyst would. Then auto-generate the incident report.

Took me a few weeks to get the full pipeline working. The hardest part was honestly getting the AI prompts right so the output was actually useful and not just generic advice.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Anthropic](https://img.shields.io/badge/AI-Anthropic%20Claude-orange)
![License](https://img.shields.io/badge/License-MIT-green)

---

## What this does

A SOC Tier 2 analyst spends most of their day doing these things:
- Looking at a queue of alerts and deciding which are real threats
- Pulling threat intelligence on suspicious IPs/domains
- Writing up incident reports
- Escalating critical things to Tier 3 / IR team

This project automates all of that, and I added AI-assisted triage so each alert gets a proper analysis — severity confirmation, MITRE ATT&CK mapping, recommended response steps, and escalation decision.

| What a real SOC T2 does | What I built |
|---|---|
| Monitor SIEM alert queue | `log_monitor.py` — 7 detection rules that flag suspicious patterns |
| Investigate & triage alerts | `ai_triage.py` — sends alerts to Claude AI for analysis |
| Threat intel lookup | `threat_intel.py` — AbuseIPDB + VirusTotal enrichment |
| Write incident reports | `report_generator.py` — NIST-format IR reports auto-generated |
| Analyze network traffic | `packet_analyzer.py` — live capture + analysis with Scapy |
| Extract IOCs | `ioc_extractor.py` — pulls IPs, domains, hashes from raw logs |
| Monitor dashboard | `dashboard.py` — terminal SOC dashboard with rich library |

---

## How it works (architecture)

```
Home Network / Simulated Logs
           |
           v
    log_generator.py          <-- generates realistic syslog, auth, firewall logs
           |
           v
    log_monitor.py            <-- 7 SIEM-style detection rules
           |
           +---------> ioc_extractor.py   (pulls indicators from logs)
           |
           v
    threat_intel.py           <-- IP reputation via AbuseIPDB/VirusTotal
           |
           v
    ai_triage.py              <-- Claude AI analyzes each alert
           |                      (severity, MITRE, TP/FP verdict, actions)
           v
    report_generator.py       <-- writes full incident report
           |
           v
    dashboard.py              <-- terminal SOC view of everything
```

---

## Setup

```bash
git clone https://github.com/yourusername/soc-ai-analyst
cd soc-ai-analyst
pip install -r requirements.txt
```

API keys are optional — everything runs in demo mode without them. But to get real AI triage working:

```bash
cp .env.example .env
# add your keys to .env:
# ANTHROPIC_API_KEY   -- get free at console.anthropic.com
# ABUSEIPDB_API_KEY   -- free tier at abuseipdb.com (1000 checks/day)
# VIRUSTOTAL_API_KEY  -- free tier at virustotal.com (4 req/min)
```

Run the full pipeline with one command:

```bash
python src/demo_pipeline.py
```

Or run each step separately:

```bash
python src/log_generator.py     # generate logs
python src/log_monitor.py       # detect threats
python src/threat_intel.py      # enrich with threat intel
python src/ai_triage.py         # AI triage
python src/report_generator.py  # write IR report
python src/dashboard.py         # view dashboard
```

---

## Project layout

```
soc-ai-analyst/
├── src/
│   ├── log_generator.py        # simulate SSH brute force, port scans, DNS tunneling etc.
│   ├── log_monitor.py          # detection rules (brute force, port scan, c2 beacon, etc.)
│   ├── ai_triage.py            # the main AI integration — Claude analyzes each alert
│   ├── threat_intel.py         # AbuseIPDB + VirusTotal lookups
│   ├── ioc_extractor.py        # regex-based IOC extraction from raw logs
│   ├── report_generator.py     # builds markdown incident reports
│   ├── packet_analyzer.py      # scapy packet capture and traffic analysis
│   ├── dashboard.py            # rich terminal dashboard
│   └── demo_pipeline.py        # runs everything in order
├── logs/
│   └── sample_alerts.json      # example output from the detection engine
├── reports/
│   └── sample_report.md        # example of a generated incident report
├── docs/
│   └── MITRE_mappings.md       # notes on which ATT&CK techniques map to which rules
├── requirements.txt
├── .env.example
└── README.md
```

---

## The AI triage part

This is the part I'm most proud of. Each alert gets sent to Claude with all the context — the raw log, the threat intel data, what rule triggered it — and it comes back with a real analysis.

The prompt I landed on after a lot of iteration:

```python
prompt = f"""
You are a SOC Analyst Tier 2 with 8 years of experience.
Analyze this security alert and respond ONLY in JSON.

Alert: {alert['rule_name']}
Source IP: {alert['src_ip']}
MITRE Technique: {alert['mitre_tid']} - {alert['mitre_name']}
Threat Intel: abuse score {intel['abuse_score']}/100, {intel['reports']} reports
Description: {alert['description']}

Evidence logs:
{evidence}

Return JSON with: confirmed_severity, verdict (TRUE_POSITIVE/FALSE_POSITIVE),
confidence %, mitre_technique, attack_summary, immediate_actions (3 steps),
escalate (bool), escalation_reason, analyst_notes
"""
```

Example output for an SSH brute force alert:

```json
{
  "confirmed_severity": "HIGH",
  "verdict": "TRUE_POSITIVE",
  "confidence": 94,
  "mitre_technique": {
    "tid": "T1110.001",
    "name": "Brute Force: Password Guessing",
    "tactic": "Credential Access"
  },
  "attack_summary": "External IP 45.142.212.100 made 25 failed SSH attempts against user 'admin' in under 3 minutes. Volume and regularity confirm automated tooling, likely Hydra or Medusa. IP has 412 abuse reports on AbuseIPDB.",
  "immediate_actions": [
    "Block 45.142.212.100 at firewall: iptables -A INPUT -s 45.142.212.100 -j DROP",
    "Check if any attempts succeeded: grep 'Accepted' /var/log/auth.log | grep 45.142.212.100",
    "Enable fail2ban if not active: sudo systemctl enable --now fail2ban"
  ],
  "escalate": true,
  "escalation_reason": "Known brute-force botnet IP, automated attack pattern — check for successful logins",
  "analyst_notes": "Also verify SSH is not exposed publicly if not needed. Consider moving to non-standard port or disabling password auth entirely."
}
```

---

## Sample detections

These are the attack types the detection engine catches:

| Alert | MITRE ID | Severity | Description |
|---|---|---|---|
| SSH Brute Force | T1110.001 | HIGH | >5 failed logins from same external IP |
| Port Scan | T1046 | MEDIUM | >6 distinct ports scanned from one IP |
| DNS Tunneling | T1071.004 | HIGH | Long subdomains + TXT queries = data exfil via DNS |
| New Local User | T1136.001 | HIGH | useradd event on server = persistence mechanism |
| Suspicious Sudo | T1548.003 | CRITICAL | sudo with /etc/shadow, nc, chmod 777, etc. |
| Known Bad IP | T1071.001 | CRITICAL | any traffic to/from IPs in threat intel feeds |
| C2 Beaconing | T1041 | CRITICAL | repeated periodic outbound to same external IP |

---

## Things I learned building this

- Writing SIEM detection rules is harder than it looks. Getting the thresholds right to avoid false positives takes a lot of tuning.
- The MITRE ATT&CK framework is actually really useful once you start mapping real behaviors to techniques. Makes incident reports way clearer.
- Regex for IOC extraction from raw logs is messy. There are edge cases everywhere — IP-looking strings in version numbers, domains that are actually just hostnames, etc.
- Prompting an AI model for structured security analysis requires being very specific about output format. I went through probably 15 iterations of the prompt before I got reliable JSON back.
- Scapy is powerful but requires root, so most of the live capture testing I did on my Raspberry Pi running as a network monitor.

---

## Stuff I want to add

- [ ] Integrate with Elasticsearch so alerts are queryable
- [ ] Add Sigma rule support so I can write rules in the industry-standard format
- [ ] YARA rule scanning for file-based detections
- [ ] Slack/Discord webhook notifications for critical alerts
- [ ] Actually deploy this on my Pi and run it 24/7 on my home network

---

## Requirements

- Python 3.10+
- See `requirements.txt` for packages
- Optional: Anthropic API key, AbuseIPDB key, VirusTotal key (all have free tiers)
- Optional: root/sudo for live packet capture with Scapy

---

*All logs in this repo are simulated. No real user data was captured or stored.*
