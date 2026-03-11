"""
ai_triage.py

The main AI part of this project.

Each alert from the SIEM gets sent to Claude (Anthropic's API) with all the
context — the raw logs, threat intel data, what rule triggered it — and the AI
comes back with a proper triage analysis like a Tier 2 analyst would write.

Took me way longer than expected to get the prompts right. First few versions
kept returning markdown instead of JSON, or the severity field would be
inconsistent ("HIGH" vs "High" vs "high"). Had to be really explicit in the
prompt about the exact format I wanted.

Also learned that giving it a "role" at the start ("You are a SOC analyst with
8 years experience") actually does make the output noticeably better. Weird but
it works.

The simulated responses at the bottom are for demo mode when no API key is set.
I wrote them based on what I'd expect a real analyst to say for each alert type.

TODO: try batching multiple alerts into one API call to save on costs
TODO: add a feedback loop — if I mark something as wrong, retrain the prompt
"""

import json
import os
import time
from dotenv import load_dotenv

load_dotenv()

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False


# ─── Prompt Template ──────────────────────────────────────────────────────────

SOC_ANALYST_SYSTEM_PROMPT = """You are an expert SOC Analyst Tier 2 with 8 years of experience in incident response, threat hunting, and security operations. You are analyzing security alerts from a home lab that replicates enterprise SOC workflows.

Your analysis must be structured, concise, and actionable. You understand MITRE ATT&CK framework deeply and always map alerts to techniques. You distinguish true positives from false positives based on context and evidence.

Always respond in valid JSON format only."""


def build_triage_prompt(alert: dict, threat_intel: dict = None) -> str:
    intel_section = ""
    if threat_intel:
        intel_section = f"""
Threat Intelligence:
  - IP Reputation Score: {threat_intel.get('abuse_score', 'N/A')}/100
  - Reports on this IP: {threat_intel.get('reports', 'N/A')}
  - Known threat categories: {threat_intel.get('categories', 'N/A')}
  - Previously seen in attacks: {threat_intel.get('known_attacker', False)}
"""

    evidence_text = "\n".join(
        f"  [{i+1}] {e.get('raw_log', '')}"
        for i, e in enumerate(alert.get("all_evidence", [])[:3])
    )

    return f"""Analyze this security alert from our SIEM and provide a complete triage assessment.

=== ALERT DETAILS ===
Alert ID: {alert['alert_id']}
Rule: {alert['rule_name']} (Rule {alert['rule_id']})
Severity: {alert['severity']}
Source IP: {alert['src_ip']}
MITRE Technique: {alert['mitre_tid']} - {alert['mitre_name']}
Description: {alert['description']}
{intel_section}
=== EVIDENCE LOGS ({alert['evidence_count']} entries) ===
{evidence_text}

=== TASK ===
Respond ONLY with a JSON object in exactly this format:
{{
  "confirmed_severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "verdict": "TRUE_POSITIVE|FALSE_POSITIVE|NEEDS_INVESTIGATION",
  "confidence": 85,
  "mitre_technique": {{
    "tid": "T1110.001",
    "name": "Brute Force: Password Guessing",
    "tactic": "Credential Access"
  }},
  "attack_summary": "2-3 sentence plain English explanation of what is happening",
  "immediate_actions": [
    "Action 1 — specific and actionable",
    "Action 2 — specific and actionable",
    "Action 3 — specific and actionable"
  ],
  "escalate": true,
  "escalation_reason": "Why this needs escalation OR null if not needed",
  "analyst_notes": "Any additional context, false positive indicators, or investigation tips"
}}"""


# ─── Simulated AI responses (fallback when no API key) ────────────────────────

SIMULATED_RESPONSES = {
    "001": {
        "confirmed_severity": "HIGH",
        "verdict": "TRUE_POSITIVE",
        "confidence": 94,
        "mitre_technique": {"tid": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
        "attack_summary": "An external threat actor is conducting an automated SSH brute force attack against the home server. The volume and pattern of failed attempts (25+ in minutes) is consistent with automated credential stuffing tools like Hydra or Medusa. The target username 'admin' is commonly attacked.",
        "immediate_actions": [
            "Block source IP at firewall immediately: iptables -A INPUT -s {src_ip} -j DROP",
            "Enable fail2ban if not already active: sudo systemctl enable --now fail2ban",
            "Review SSH config — disable password auth, enforce key-only: PasswordAuthentication no in /etc/ssh/sshd_config"
        ],
        "escalate": True,
        "escalation_reason": "IP matches known brute force botnet; pattern suggests automated attack targeting credential reuse",
        "analyst_notes": "Check if any attempts succeeded by reviewing auth.log for 'Accepted password' entries from this IP."
    },
    "002": {
        "confirmed_severity": "MEDIUM",
        "verdict": "TRUE_POSITIVE",
        "confidence": 88,
        "mitre_technique": {"tid": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        "attack_summary": "A systematic port scan was performed against the home server, probing 12 common service ports. This is reconnaissance behavior typically preceding an exploitation attempt. The scan pattern suggests an automated scanner rather than manual enumeration.",
        "immediate_actions": [
            "Block the scanning IP at perimeter firewall",
            "Audit which discovered ports/services are actually needed — disable unnecessary ones",
            "Enable port scan detection in fail2ban or IDS"
        ],
        "escalate": False,
        "escalation_reason": None,
        "analyst_notes": "No exploitation attempts detected following the scan yet. Monitor for follow-up activity from this IP over next 24 hours."
    },
    "003": {
        "confirmed_severity": "HIGH",
        "verdict": "TRUE_POSITIVE",
        "confidence": 91,
        "mitre_technique": {"tid": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control"},
        "attack_summary": "A host on the internal network is generating DNS queries with anomalously long, randomized subdomains — a hallmark of DNS tunneling. This technique encodes data in DNS queries to bypass firewalls. The repeated TXT record queries confirm this is data exfiltration or C2 communication via DNS.",
        "immediate_actions": [
            "Immediately isolate the affected host from the network",
            "Block outbound DNS to external resolvers; force all DNS through controlled internal resolver",
            "Capture full packet dump of DNS traffic from affected host for forensics"
        ],
        "escalate": True,
        "escalation_reason": "DNS tunneling indicates a compromised host communicating with C2 — potential active intrusion requiring immediate containment",
        "analyst_notes": "Investigate what processes on the affected host are generating these queries. Tools like iodine or dnscat2 produce this exact pattern."
    },
    "004": {
        "confirmed_severity": "HIGH",
        "verdict": "TRUE_POSITIVE",
        "confidence": 87,
        "mitre_technique": {"tid": "T1136.001", "name": "Create Account: Local Account", "tactic": "Persistence"},
        "attack_summary": "A new local user account was created on the server, which is a classic persistence mechanism used by attackers after initial compromise. Unless this was an authorized administrative action, this strongly indicates an attacker has established a foothold and is creating a backdoor account for future access.",
        "immediate_actions": [
            "Immediately disable/delete the new account: sudo userdel -r {username}",
            "Audit who has sudo access and review /etc/sudoers",
            "Check if the account was added to any privileged groups: groups {username}"
        ],
        "escalate": True,
        "escalation_reason": "Unauthorized account creation = confirmed persistence mechanism; host should be considered compromised",
        "analyst_notes": "Check /var/log/auth.log for what user/process created this account. This may be a follow-on action after initial access via brute force."
    },
    "005": {
        "confirmed_severity": "CRITICAL",
        "verdict": "TRUE_POSITIVE",
        "confidence": 96,
        "mitre_technique": {"tid": "T1548.003", "name": "Abuse Elevation Control Mechanism: Sudo", "tactic": "Privilege Escalation"},
        "attack_summary": "A user executed highly suspicious sudo commands including accessing /etc/shadow (password hashes) and spawning netcat listeners. These are textbook post-exploitation actions: credential dumping and establishing reverse shell backdoors. This is a critical incident indicating active hands-on attacker activity.",
        "immediate_actions": [
            "IMMEDIATELY isolate this host from the network",
            "Terminate any active sessions: who -a then kill all sessions for this user",
            "Change all passwords — attacker may have dumped /etc/shadow hashes"
        ],
        "escalate": True,
        "escalation_reason": "CRITICAL: Active attacker on system — credential dumping + reverse shell = hands-on-keyboard attack in progress",
        "analyst_notes": "This is a Priority 1 incident. The combination of /etc/shadow access and nc listener strongly indicates post-exploitation. Treat this system as fully compromised."
    },
    "006": {
        "confirmed_severity": "CRITICAL",
        "verdict": "TRUE_POSITIVE",
        "confidence": 92,
        "mitre_technique": {"tid": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
        "attack_summary": "A device on the network is communicating with an IP address flagged in multiple threat intelligence feeds as malware infrastructure. This traffic pattern is consistent with an infected device checking in with its command-and-control server.",
        "immediate_actions": [
            "Identify which device is generating this traffic using ARP tables and DHCP logs",
            "Immediately block the C2 IP at the router/firewall level",
            "Isolate the suspected compromised device from the network"
        ],
        "escalate": True,
        "escalation_reason": "Active C2 communication = confirmed malware infection; device containment required immediately",
        "analyst_notes": "Run malware scan on identified host. Check for recently installed software, browser extensions, or scheduled tasks."
    },
    "007": {
        "confirmed_severity": "CRITICAL",
        "verdict": "TRUE_POSITIVE",
        "confidence": 89,
        "mitre_technique": {"tid": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
        "attack_summary": "Regular, periodic outbound connections from an internal host to an external IP exhibit beaconing behavior — a pattern consistent with malware 'calling home' on a schedule. The regularity distinguishes this from normal user traffic and suggests automated malware activity.",
        "immediate_actions": [
            "Block the destination IP at the firewall immediately",
            "Capture network traffic from the source host for malware analysis",
            "Run EDR/antivirus scan on the source host"
        ],
        "escalate": True,
        "escalation_reason": "Beaconing to known-bad infrastructure = active malware infection with C2 communication",
        "analyst_notes": "Calculate the beacon interval — consistent intervals (e.g., every 60s) confirm automated malware vs. human activity."
    }
}


# ─── AI Triage Engine ──────────────────────────────────────────────────────────

class AITriageEngine:
    def __init__(self):
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.use_real_ai = bool(self.api_key and ANTHROPIC_AVAILABLE)
        
        if self.use_real_ai:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            print("[+] Claude AI connected — using real AI triage")
        else:
            print("[*] No API key found — using simulated AI responses (demo mode)")
            print("    To use real AI: add ANTHROPIC_API_KEY to your .env file")

    def triage_alert(self, alert: dict, threat_intel: dict = None) -> dict:
        """Triage a single alert using Claude AI or simulated response"""
        
        if self.use_real_ai:
            return self._real_ai_triage(alert, threat_intel)
        else:
            return self._simulated_triage(alert)

    def _real_ai_triage(self, alert: dict, threat_intel: dict = None) -> dict:
        """Call Claude API for real AI triage"""
        try:
            prompt = build_triage_prompt(alert, threat_intel)
            message = self.client.messages.create(
                model="claude-opus-4-5",
                max_tokens=1024,
                system=SOC_ANALYST_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )
            response_text = message.content[0].text
            # Strip markdown fences if present
            response_text = response_text.replace("```json", "").replace("```", "").strip()
            return json.loads(response_text)
        except Exception as e:
            print(f"    [!] AI API error: {e} — falling back to simulation")
            return self._simulated_triage(alert)

    def _simulated_triage(self, alert: dict) -> dict:
        """Return realistic simulated AI analysis"""
        rule_id = alert.get("rule_id", "001")
        response = SIMULATED_RESPONSES.get(rule_id, SIMULATED_RESPONSES["001"]).copy()
        # Fill in dynamic values
        for i, action in enumerate(response["immediate_actions"]):
            response["immediate_actions"][i] = action.format(
                src_ip=alert.get("src_ip", "UNKNOWN_IP"),
                username=alert.get("description", "").split("'")[1] if "'" in alert.get("description", "") else "user"
            )
        return response

    def triage_all_alerts(self, alerts: list) -> list:
        """Triage all alerts and return enriched results"""
        print("\n" + "=" * 60)
        print("  🤖 AI TRIAGE ENGINE — ANALYZING ALERTS")
        print("=" * 60)
        
        enriched = []
        for i, alert in enumerate(alerts):
            print(f"\n[{i+1}/{len(alerts)}] Triaging: {alert['rule_name']}")
            print(f"    Source IP: {alert['src_ip']}")
            
            ai_analysis = self.triage_alert(alert)
            
            enriched_alert = {**alert, "ai_analysis": ai_analysis}
            enriched.append(enriched_alert)
            
            verdict = ai_analysis.get("verdict", "UNKNOWN")
            severity = ai_analysis.get("confirmed_severity", "UNKNOWN")
            confidence = ai_analysis.get("confidence", 0)
            
            verdict_color = "\033[91m" if verdict == "TRUE_POSITIVE" else "\033[92m"
            print(f"    {verdict_color}Verdict: {verdict} ({confidence}% confidence)\033[0m")
            print(f"    Severity: {severity}")
            print(f"    Escalate: {'🚨 YES' if ai_analysis.get('escalate') else '✅ No'}")
            
            if self.use_real_ai:
                time.sleep(0.5)  # Rate limiting
        
        # Save results
        os.makedirs("logs", exist_ok=True)
        with open("logs/triage_results.json", "w") as f:
            json.dump(enriched, f, indent=2)
        
        print(f"\n[+] AI triage complete. Results saved to logs/triage_results.json")
        
        # Summary
        tp = sum(1 for a in enriched if a["ai_analysis"].get("verdict") == "TRUE_POSITIVE")
        fp = sum(1 for a in enriched if a["ai_analysis"].get("verdict") == "FALSE_POSITIVE")
        esc = sum(1 for a in enriched if a["ai_analysis"].get("escalate"))
        print(f"\n    True Positives: {tp}")
        print(f"    False Positives: {fp}")
        print(f"    Needs Escalation: {esc}")
        
        return enriched


def run_triage():
    with open("logs/alerts.json") as f:
        alerts = json.load(f)
    
    engine = AITriageEngine()
    return engine.triage_all_alerts(alerts)


if __name__ == "__main__":
    run_triage()
