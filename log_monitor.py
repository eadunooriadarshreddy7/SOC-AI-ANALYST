"""
log_monitor.py

This is the "SIEM detection engine" part of my home lab.
Reads logs and applies detection rules to find suspicious stuff.

I modeled the rules after what I've read about real SIEM detections
(mostly from SANS, the MITRE ATT&CK site, and some Splunk blog posts).

Detection rules:
  Rule 001 - SSH brute force: same IP, >5 failures
  Rule 002 - Port scan: same IP hitting >8 different ports
  Rule 003 - DNS tunneling: long subdomains / TXT queries
  Rule 004 - New local user created (useradd event)
  Rule 005 - Suspicious sudo commands (shadow file, netcat, etc)
  Rule 006 - Traffic to/from known bad IPs
  Rule 007 - Beaconing pattern: repeated outbound to same external IP

The thresholds took some tweaking — I kept getting false positives on rule 002
until I bumped the port threshold from 5 to 8.

TODO: add time-windowing so rule 001 only triggers within a 5-minute window
      right now it just counts across all logs which isn't realistic
"""

import json
import os
from collections import defaultdict
from datetime import datetime

ALERT_COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH":     "\033[93m",  # Yellow
    "MEDIUM":   "\033[94m",  # Blue
    "LOW":      "\033[92m",  # Green
    "INFO":     "\033[0m",   # Reset
    "RESET":    "\033[0m",
}

KNOWN_BAD_IPS = {
    "185.220.101.47": "Tor Exit Node - associated with anonymized attacks",
    "45.142.212.100": "Reported brute force source (AbuseIPDB score: 98)",
    "194.165.16.11":  "Port scanning botnet member",
    "91.92.251.103":  "Known malware C2 server",
    "179.43.128.10":  "Botnet infrastructure",
    "103.252.118.22": "Anonymous proxy / VPN abuse",
}

SUSPICIOUS_SUDO_COMMANDS = [
    "/etc/shadow", "/etc/passwd", "nc ", "netcat", "ncat",
    "wget http", "curl http", "chmod 777", "base64", "python -c",
    "/dev/tcp", "mkfifo", "bash -i"
]


def color(severity, text):
    return f"{ALERT_COLORS.get(severity, '')}{text}{ALERT_COLORS['RESET']}"


class Alert:
    def __init__(self, rule_id, rule_name, severity, description, src_ip, evidence, mitre_tid, mitre_name):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.severity = severity
        self.description = description
        self.src_ip = src_ip
        self.evidence = evidence  # list of relevant log entries
        self.mitre_tid = mitre_tid
        self.mitre_name = mitre_name
        self.timestamp = datetime.now().isoformat()
        self.alert_id = f"ALT-{rule_id}-{hash(src_ip + self.timestamp) % 10000:04d}"

    def to_dict(self):
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "src_ip": self.src_ip,
            "mitre_tid": self.mitre_tid,
            "mitre_name": self.mitre_name,
            "timestamp": self.timestamp,
            "evidence_count": len(self.evidence),
            "sample_log": self.evidence[0]["raw_log"] if self.evidence else "",
            "all_evidence": self.evidence,
        }


class SIEMDetectionEngine:
    def __init__(self, log_file="logs/network_logs.json"):
        self.log_file = log_file
        self.logs = []
        self.alerts = []

    def load_logs(self):
        with open(self.log_file) as f:
            self.logs = json.load(f)
        print(f"[*] Loaded {len(self.logs)} log entries from {self.log_file}")

    # ─── Detection Rules ───────────────────────────────────────────────────

    def rule_001_ssh_brute_force(self):
        """Detect SSH brute force: >5 failures from same IP"""
        failed = defaultdict(list)
        for log in self.logs:
            if log["type"] == "brute_force":
                failed[log["src_ip"]].append(log)

        for ip, entries in failed.items():
            if len(entries) >= 5:
                alert = Alert(
                    rule_id="001",
                    rule_name="SSH Brute Force Detected",
                    severity="HIGH",
                    description=f"IP {ip} made {len(entries)} failed SSH login attempts targeting user '{entries[0]['username']}'",
                    src_ip=ip,
                    evidence=entries[:5],
                    mitre_tid="T1110.001",
                    mitre_name="Brute Force: Password Guessing",
                )
                self.alerts.append(alert)
                print(color("HIGH", f"  [!] RULE 001 TRIGGERED — SSH Brute Force from {ip} ({len(entries)} attempts)"))

    def rule_002_port_scan(self):
        """Detect port scan: >6 unique ports from same IP"""
        scans = defaultdict(set)
        scan_logs = defaultdict(list)
        for log in self.logs:
            if log["type"] == "port_scan":
                scans[log["src_ip"]].add(log["dst_port"])
                scan_logs[log["src_ip"]].append(log)

        for ip, ports in scans.items():
            if len(ports) >= 6:
                alert = Alert(
                    rule_id="002",
                    rule_name="Port Scan Detected",
                    severity="MEDIUM",
                    description=f"IP {ip} scanned {len(ports)} ports: {sorted(ports)}",
                    src_ip=ip,
                    evidence=scan_logs[ip][:6],
                    mitre_tid="T1046",
                    mitre_name="Network Service Discovery",
                )
                self.alerts.append(alert)
                print(color("MEDIUM", f"  [!] RULE 002 TRIGGERED — Port Scan from {ip} ({len(ports)} ports)"))

    def rule_003_dns_anomaly(self):
        """Detect DNS tunneling: unusual TXT queries with long subdomains"""
        dns_logs = defaultdict(list)
        for log in self.logs:
            if log["type"] == "dns_tunneling":
                dns_logs[log["src_ip"]].append(log)

        for ip, entries in dns_logs.items():
            if len(entries) >= 3:
                alert = Alert(
                    rule_id="003",
                    rule_name="Possible DNS Tunneling",
                    severity="HIGH",
                    description=f"Host {ip} made {len(entries)} suspicious DNS TXT queries with anomalously long subdomains",
                    src_ip=ip,
                    evidence=entries[:4],
                    mitre_tid="T1071.004",
                    mitre_name="Application Layer Protocol: DNS",
                )
                self.alerts.append(alert)
                print(color("HIGH", f"  [!] RULE 003 TRIGGERED — DNS Tunneling suspected from {ip}"))

    def rule_004_new_user_account(self):
        """Detect unauthorized user account creation"""
        for log in self.logs:
            if log["type"] == "new_user":
                alert = Alert(
                    rule_id="004",
                    rule_name="New User Account Created",
                    severity="HIGH",
                    description=f"New system user '{log['username']}' created — potential persistence mechanism",
                    src_ip=log["src_ip"],
                    evidence=[log],
                    mitre_tid="T1136.001",
                    mitre_name="Create Account: Local Account",
                )
                self.alerts.append(alert)
                print(color("HIGH", f"  [!] RULE 004 TRIGGERED — New user '{log['username']}' created"))

    def rule_005_sudo_abuse(self):
        """Detect suspicious sudo commands"""
        for log in self.logs:
            if log["type"] == "sudo_abuse":
                matched_cmd = next(
                    (c for c in SUSPICIOUS_SUDO_COMMANDS if c in log["raw_log"].lower()), "suspicious command"
                )
                alert = Alert(
                    rule_id="005",
                    rule_name="Suspicious Sudo Command",
                    severity="CRITICAL",
                    description=f"User '{log['username']}' executed high-risk sudo command containing '{matched_cmd}'",
                    src_ip=log["src_ip"],
                    evidence=[log],
                    mitre_tid="T1548.003",
                    mitre_name="Abuse Elevation Control Mechanism: Sudo",
                )
                self.alerts.append(alert)
                print(color("CRITICAL", f"  [!] RULE 005 TRIGGERED — Suspicious sudo by '{log['username']}'"))

    def rule_006_known_bad_ip(self):
        """Detect communication with known bad IPs"""
        seen = set()
        for log in self.logs:
            ip = log.get("src_ip") or log.get("dst_ip")
            for bad_ip, reason in KNOWN_BAD_IPS.items():
                if bad_ip in (log.get("src_ip", ""), log.get("dst_ip", "")) and bad_ip not in seen:
                    seen.add(bad_ip)
                    alert = Alert(
                        rule_id="006",
                        rule_name="Known Malicious IP Communication",
                        severity="CRITICAL",
                        description=f"Traffic involving known-bad IP {bad_ip}: {reason}",
                        src_ip=bad_ip,
                        evidence=[log],
                        mitre_tid="T1071.001",
                        mitre_name="Application Layer Protocol: Web Protocols",
                    )
                    self.alerts.append(alert)
                    print(color("CRITICAL", f"  [!] RULE 006 TRIGGERED — Known-bad IP {bad_ip} detected"))

    def rule_007_c2_beaconing(self):
        """Detect C2 beaconing: repeated outbound to same IP"""
        beacon_counts = defaultdict(list)
        for log in self.logs:
            if log["type"] == "c2_beacon":
                beacon_counts[log["dst_ip"]].append(log)

        for dst_ip, entries in beacon_counts.items():
            if len(entries) >= 3:
                src = entries[0]["src_ip"]
                alert = Alert(
                    rule_id="007",
                    rule_name="Outbound C2 Beaconing Pattern",
                    severity="CRITICAL",
                    description=f"Host {src} made {len(entries)} regular outbound connections to {dst_ip} — possible C2 beacon",
                    src_ip=src,
                    evidence=entries[:4],
                    mitre_tid="T1041",
                    mitre_name="Exfiltration Over C2 Channel",
                )
                self.alerts.append(alert)
                print(color("CRITICAL", f"  [!] RULE 007 TRIGGERED — C2 Beaconing from {src} → {dst_ip}"))

    # ─── Run All Rules ──────────────────────────────────────────────────────

    def run_all_rules(self):
        print("\n" + "=" * 60)
        print("  🔍 SIEM DETECTION ENGINE — RUNNING RULES")
        print("=" * 60)
        self.rule_001_ssh_brute_force()
        self.rule_002_port_scan()
        self.rule_003_dns_anomaly()
        self.rule_004_new_user_account()
        self.rule_005_sudo_abuse()
        self.rule_006_known_bad_ip()
        self.rule_007_c2_beaconing()

        print("\n" + "=" * 60)
        print(f"  📊 DETECTION COMPLETE: {len(self.alerts)} alerts generated")
        print("=" * 60)

        # Count by severity
        counts = defaultdict(int)
        for a in self.alerts:
            counts[a.severity] += 1
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if counts[sev]:
                print(color(sev, f"  {sev}: {counts[sev]} alert(s)"))

    def save_alerts(self):
        os.makedirs("logs", exist_ok=True)
        data = [a.to_dict() for a in self.alerts]
        with open("logs/alerts.json", "w") as f:
            json.dump(data, f, indent=2)
        print(f"\n[+] Alerts saved to logs/alerts.json")
        return data


def run_monitor():
    engine = SIEMDetectionEngine()
    engine.load_logs()
    engine.run_all_rules()
    return engine.save_alerts()


if __name__ == "__main__":
    run_monitor()
