"""
log_generator.py

Generates fake-but-realistic network/auth logs for my home lab SIEM.
Covers the main attack types I want to practice detecting:
  - SSH brute force (most common thing hitting home servers)
  - Port scanning
  - DNS tunneling (learned about this watching a SANS talk)
  - Suspicious sudo usage
  - New user account creation (persistence)
  - C2 beaconing

NOTE: all IPs/logs here are simulated. nothing real is getting captured/stored.

TODO: add web server log simulation (nginx access logs would be good to have)
TODO: maybe add failed sudo attempts too, not just successful bad commands
"""

import json
import random
import datetime
import os
import string

# Simple inline faker replacement
class _Fake:
    _hex_chars = string.hexdigits[:16]
    _tlds = ["com", "net", "org", "io", "ru", "cn", "br"]
    _words = ["update", "cdn", "api", "data", "sync", "beacon", "check", "relay"]
    _names = ["alice", "bob", "charlie", "dave", "eve", "frank", "grace", "hank"]
    def hexify(self, text="^^"):
        return "".join(random.choice(self._hex_chars) if c == "^" else c for c in text)
    def domain_name(self):
        return f"{''.join(random.choices(string.ascii_lowercase, k=8))}.{random.choice(self._tlds)}"
    def user_name(self):
        return random.choice(self._names) + str(random.randint(10, 99))

fake = _Fake()

# --- Threat actor IPs (simulated) ---
THREAT_IPS = [
    "185.220.101.47",  # Known Tor exit node
    "45.142.212.100",  # Brute force source
    "194.165.16.11",   # Port scanner
    "91.92.251.103",   # Malware C2
    "179.43.128.10",   # Botnet node
    "103.252.118.22",  # Proxy/VPN abuse
]

HOME_IPS = ["192.168.1." + str(i) for i in range(2, 20)]
INTERNAL_SERVER = "192.168.1.1"

USERNAMES = ["admin", "root", "ubuntu", "pi", "user", "test", "guest", "oracle"]
SERVICES = ["sshd", "nginx", "apache2", "mysqld", "vsftpd", "postfix", "cron", "sudo"]

MITRE_ATTACKS = {
    "brute_force":    {"tid": "T1110.001", "name": "Brute Force: Password Guessing"},
    "port_scan":      {"tid": "T1046",     "name": "Network Service Discovery"},
    "dns_tunneling":  {"tid": "T1071.004", "name": "Application Layer Protocol: DNS"},
    "c2_beacon":      {"tid": "T1071.001", "name": "Application Layer Protocol: Web Protocols"},
    "exfiltration":   {"tid": "T1041",     "name": "Exfiltration Over C2 Channel"},
    "new_user":       {"tid": "T1136.001", "name": "Create Account: Local Account"},
    "sudo_abuse":     {"tid": "T1548.003", "name": "Abuse Elevation: Sudo and Sudo Caching"},
    "log_clear":      {"tid": "T1070.002", "name": "Indicator Removal: Clear Linux Logs"},
}


def timestamp(minutes_ago=0):
    t = datetime.datetime.now() - datetime.timedelta(minutes=random.randint(0, minutes_ago or 1))
    return t.strftime("%b %d %H:%M:%S")


def generate_brute_force_logs(count=20):
    """Simulate SSH brute force attack from external IP"""
    logs = []
    src_ip = random.choice(THREAT_IPS)
    target_user = random.choice(USERNAMES)
    for i in range(count):
        log = {
            "timestamp": timestamp(30),
            "host": "homeserver",
            "service": "sshd",
            "type": "brute_force",
            "message": f"Failed password for {target_user} from {src_ip} port {random.randint(30000,60000)} ssh2",
            "src_ip": src_ip,
            "dst_ip": INTERNAL_SERVER,
            "dst_port": 22,
            "username": target_user,
            "raw_log": f"{timestamp(30)} homeserver sshd[{random.randint(1000,9999)}]: Failed password for {target_user} from {src_ip} port {random.randint(30000,60000)} ssh2",
            "mitre": MITRE_ATTACKS["brute_force"],
            "severity": "HIGH",
        }
        logs.append(log)
    return logs


def generate_port_scan_logs():
    """Simulate port scan from external IP"""
    logs = []
    src_ip = random.choice(THREAT_IPS)
    for port in [21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200]:
        log = {
            "timestamp": timestamp(60),
            "host": "homeserver",
            "service": "firewall",
            "type": "port_scan",
            "message": f"Blocked inbound connection from {src_ip} to port {port}",
            "src_ip": src_ip,
            "dst_ip": INTERNAL_SERVER,
            "dst_port": port,
            "username": None,
            "raw_log": f"{timestamp(60)} homeserver kernel: [UFW BLOCK] IN=eth0 SRC={src_ip} DST={INTERNAL_SERVER} DPT={port}",
            "mitre": MITRE_ATTACKS["port_scan"],
            "severity": "MEDIUM",
        }
        logs.append(log)
    return logs


def generate_dns_tunneling_logs():
    """Simulate suspicious DNS activity (possible tunneling)"""
    logs = []
    src_ip = random.choice(HOME_IPS)
    suspicious_domain = f"data-{fake.hexify(text='^^^^^^^^')}.{fake.domain_name()}"
    for _ in range(8):
        subdomain = fake.hexify(text="^" * random.randint(20, 40))
        log = {
            "timestamp": timestamp(45),
            "host": "homeserver",
            "service": "named",
            "type": "dns_tunneling",
            "message": f"Unusual long DNS query: {subdomain}.{suspicious_domain}",
            "src_ip": src_ip,
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "username": None,
            "raw_log": f"{timestamp(45)} homeserver named[{random.randint(1000,9999)}]: query: {subdomain}.{suspicious_domain} IN TXT",
            "mitre": MITRE_ATTACKS["dns_tunneling"],
            "severity": "HIGH",
        }
        logs.append(log)
    return logs


def generate_new_user_logs():
    """Simulate unauthorized new user creation"""
    src_ip = random.choice(HOME_IPS)
    new_user = fake.user_name()
    log = {
        "timestamp": timestamp(15),
        "host": "homeserver",
        "service": "useradd",
        "type": "new_user",
        "message": f"New user account created: {new_user} (uid=1002)",
        "src_ip": src_ip,
        "dst_ip": INTERNAL_SERVER,
        "dst_port": None,
        "username": new_user,
        "raw_log": f"{timestamp(15)} homeserver useradd[{random.randint(1000,9999)}]: new user: name={new_user}, UID=1002, GID=1002",
        "mitre": MITRE_ATTACKS["new_user"],
        "severity": "HIGH",
    }
    return [log]


def generate_sudo_abuse_logs():
    """Simulate unusual sudo usage"""
    logs = []
    src_ip = random.choice(HOME_IPS)
    user = random.choice(USERNAMES)
    for cmd in ["cat /etc/shadow", "chmod 777 /etc/passwd", "nc -lvp 4444"]:
        log = {
            "timestamp": timestamp(10),
            "host": "homeserver",
            "service": "sudo",
            "type": "sudo_abuse",
            "message": f"User {user} ran suspicious sudo command: {cmd}",
            "src_ip": src_ip,
            "dst_ip": INTERNAL_SERVER,
            "dst_port": None,
            "username": user,
            "raw_log": f"{timestamp(10)} homeserver sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash -c '{cmd}'",
            "mitre": MITRE_ATTACKS["sudo_abuse"],
            "severity": "CRITICAL",
        }
        logs.append(log)
    return logs


def generate_c2_beacon_logs():
    """Simulate C2 beaconing behavior"""
    logs = []
    src_ip = random.choice(HOME_IPS)
    c2_ip = random.choice(THREAT_IPS)
    for _ in range(6):
        log = {
            "timestamp": timestamp(120),
            "host": "homeserver",
            "service": "firewall",
            "type": "c2_beacon",
            "message": f"Regular outbound connection to known-bad IP {c2_ip}:443 (beaconing pattern)",
            "src_ip": src_ip,
            "dst_ip": c2_ip,
            "dst_port": 443,
            "username": None,
            "raw_log": f"{timestamp(120)} homeserver firewall: ALLOW OUT src={src_ip} dst={c2_ip} dpt=443 proto=TCP",
            "mitre": MITRE_ATTACKS["c2_beacon"],
            "severity": "CRITICAL",
        }
        logs.append(log)
    return logs


def generate_normal_logs(count=30):
    """Generate normal baseline traffic to make alerts stand out"""
    logs = []
    for _ in range(count):
        src = random.choice(HOME_IPS)
        log = {
            "timestamp": timestamp(180),
            "host": "homeserver",
            "service": random.choice(SERVICES),
            "type": "normal",
            "message": f"Routine system activity from {src}",
            "src_ip": src,
            "dst_ip": INTERNAL_SERVER,
            "dst_port": random.choice([80, 443, 53]),
            "username": None,
            "raw_log": f"{timestamp(180)} homeserver {random.choice(SERVICES)}[{random.randint(1000,9999)}]: Accepted connection from {src}",
            "mitre": None,
            "severity": "INFO",
        }
        logs.append(log)
    return logs


def generate_all_logs():
    """Generate a full log dataset simulating a realistic threat scenario"""
    print("[*] Generating simulated home network security logs...")
    
    all_logs = []
    all_logs.extend(generate_normal_logs(40))
    all_logs.extend(generate_brute_force_logs(25))
    all_logs.extend(generate_port_scan_logs())
    all_logs.extend(generate_dns_tunneling_logs())
    all_logs.extend(generate_new_user_logs())
    all_logs.extend(generate_sudo_abuse_logs())
    all_logs.extend(generate_c2_beacon_logs())
    
    # Shuffle to simulate realistic log stream
    random.shuffle(all_logs)
    
    os.makedirs("logs", exist_ok=True)
    with open("logs/network_logs.json", "w") as f:
        json.dump(all_logs, f, indent=2)
    
    print(f"[+] Generated {len(all_logs)} log entries")
    print(f"[+] Saved to logs/network_logs.json")
    
    # Print summary
    alert_types = {}
    for log in all_logs:
        t = log["type"]
        alert_types[t] = alert_types.get(t, 0) + 1
    
    print("\n[*] Log Summary:")
    for t, count in sorted(alert_types.items()):
        marker = "⚠️ " if t != "normal" else "✅"
        print(f"    {marker} {t}: {count} entries")
    
    return all_logs


if __name__ == "__main__":
    generate_all_logs()
