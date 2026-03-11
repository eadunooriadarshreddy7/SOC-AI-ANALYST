"""
ioc_extractor.py

Extracts Indicators of Compromise from raw log text using regex.

IOC types extracted:
  - IPv4 addresses (splits internal vs external)
  - Domain names
  - MD5 and SHA256 hashes
  - URLs
  - Email addresses
  - CVE references

The regex patterns took a while to get right. The domain one especially —
kept matching things like "3.14.159" (pi) or "1.0.0" (version numbers) as
domains. Added some filters to handle that.

Also had to exclude common internal/system domains that kept showing up
as false positives (localhost, .local, ubuntu.com from apt logs, etc.)

Inspired by how tools like CyberChef handle IOC extraction, but wanted to
build it myself to understand what's actually happening under the hood.

TODO: add YARA-style pattern matching for more complex IOCs
TODO: output in STIX format for proper threat intel sharing
"""

import re
import json
import os
from collections import defaultdict
from datetime import datetime


# ─── Regex Patterns ───────────────────────────────────────────────────────────

PATTERNS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    ),
    "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "url": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
    "email": re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b'),
    "cve": re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE),
}

INTERNAL_IP_RANGES = [
    re.compile(r'^192\.168\.'),
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
    re.compile(r'^127\.'),
]

EXCLUDE_DOMAINS = {
    "localhost", "example.com", "test.com", "local",
    "homeserver", "ubuntu.com", "debian.org"
}


def is_internal_ip(ip: str) -> bool:
    return any(pattern.match(ip) for pattern in INTERNAL_IP_RANGES)


def is_valid_domain(domain: str) -> bool:
    # Filter out things that look like version numbers or IPs
    if re.match(r'^\d+\.\d+', domain):
        return False
    if domain.lower() in EXCLUDE_DOMAINS:
        return False
    if len(domain) < 4:
        return False
    return True


class IOCExtractor:
    def __init__(self):
        self.iocs = {
            "external_ips": defaultdict(lambda: {"count": 0, "seen_in": [], "type": "External IP"}),
            "internal_ips": defaultdict(lambda: {"count": 0, "seen_in": [], "type": "Internal IP"}),
            "domains": defaultdict(lambda: {"count": 0, "seen_in": [], "type": "Domain"}),
            "urls": defaultdict(lambda: {"count": 0, "seen_in": [], "type": "URL"}),
            "hashes": defaultdict(lambda: {"count": 0, "seen_in": [], "type": "Hash"}),
            "emails": defaultdict(lambda: {"count": 0, "seen_in": [], "type": "Email"}),
            "cves": defaultdict(lambda: {"count": 0, "seen_in": [], "type": "CVE"}),
        }

    def extract_from_text(self, text: str, source: str = "unknown"):
        """Extract all IOCs from a text string"""
        
        # IPs
        for ip in PATTERNS["ipv4"].findall(text):
            if is_internal_ip(ip):
                self.iocs["internal_ips"][ip]["count"] += 1
                self.iocs["internal_ips"][ip]["seen_in"].append(source)
            else:
                self.iocs["external_ips"][ip]["count"] += 1
                self.iocs["external_ips"][ip]["seen_in"].append(source)
        
        # Domains
        for domain in PATTERNS["domain"].findall(text):
            domain = domain.lower().rstrip(".")
            if is_valid_domain(domain) and not PATTERNS["ipv4"].match(domain):
                self.iocs["domains"][domain]["count"] += 1
                self.iocs["domains"][domain]["seen_in"].append(source)
        
        # URLs
        for url in PATTERNS["url"].findall(text):
            self.iocs["urls"][url]["count"] += 1
            self.iocs["urls"][url]["seen_in"].append(source)
        
        # Hashes
        for h in PATTERNS["sha256"].findall(text):
            self.iocs["hashes"][h]["count"] += 1
            self.iocs["hashes"][h]["seen_in"].append(source)
            self.iocs["hashes"][h]["hash_type"] = "SHA256"
        
        for h in PATTERNS["md5"].findall(text):
            if h not in self.iocs["hashes"]:
                self.iocs["hashes"][h]["count"] += 1
                self.iocs["hashes"][h]["seen_in"].append(source)
                self.iocs["hashes"][h]["hash_type"] = "MD5"
        
        # CVEs
        for cve in PATTERNS["cve"].findall(text):
            self.iocs["cves"][cve.upper()]["count"] += 1
            self.iocs["cves"][cve.upper()]["seen_in"].append(source)

    def extract_from_logs(self, logs: list):
        """Process all logs and extract IOCs"""
        print("\n" + "=" * 60)
        print("  🔬 IOC EXTRACTION ENGINE")
        print("=" * 60)
        
        for log in logs:
            text = log.get("raw_log", "") + " " + log.get("message", "")
            source = f"{log.get('service', 'unknown')}:{log.get('type', 'unknown')}"
            self.extract_from_text(text, source)
        
        print(f"\n[+] Extraction complete:")
        print(f"    External IPs: {len(self.iocs['external_ips'])}")
        print(f"    Internal IPs: {len(self.iocs['internal_ips'])}")
        print(f"    Domains:      {len(self.iocs['domains'])}")
        print(f"    URLs:         {len(self.iocs['urls'])}")
        print(f"    Hashes:       {len(self.iocs['hashes'])}")
        print(f"    CVEs:         {len(self.iocs['cves'])}")

    def get_summary(self) -> dict:
        """Convert IOC data to serializable summary"""
        summary = {"extraction_time": datetime.now().isoformat(), "iocs": {}}
        
        for category, data in self.iocs.items():
            summary["iocs"][category] = []
            for indicator, info in data.items():
                entry = {
                    "indicator": indicator,
                    "type": info.get("type", category),
                    "count": info["count"],
                    "unique_sources": len(set(info["seen_in"])),
                }
                if "hash_type" in info:
                    entry["hash_type"] = info["hash_type"]
                summary["iocs"][category].append(entry)
            
            # Sort by frequency
            summary["iocs"][category].sort(key=lambda x: x["count"], reverse=True)
        
        return summary

    def print_high_value_iocs(self):
        """Print the most significant IOCs"""
        print("\n  📋 HIGH-VALUE IOCs EXTRACTED")
        print("  " + "-" * 40)
        
        # Top external IPs
        if self.iocs["external_ips"]:
            print("\n  🌐 External IPs (potential threat actors):")
            for ip, data in sorted(
                self.iocs["external_ips"].items(),
                key=lambda x: x[1]["count"], reverse=True
            )[:5]:
                print(f"    \033[91m{ip}\033[0m — seen {data['count']} times")
        
        # Domains
        if self.iocs["domains"]:
            suspicious = {k: v for k, v in self.iocs["domains"].items()
                         if v["count"] > 1 or any("dns" in s for s in v["seen_in"])}
            if suspicious:
                print("\n  🌍 Suspicious Domains:")
                for domain, data in list(suspicious.items())[:5]:
                    print(f"    \033[93m{domain}\033[0m — {data['count']} queries")


def run_ioc_extraction():
    with open("logs/network_logs.json") as f:
        logs = json.load(f)
    
    extractor = IOCExtractor()
    extractor.extract_from_logs(logs)
    extractor.print_high_value_iocs()
    
    summary = extractor.get_summary()
    os.makedirs("logs", exist_ok=True)
    with open("logs/ioc_report.json", "w") as f:
        json.dump(summary, f, indent=2)
    
    print("\n[+] Full IOC report saved to logs/ioc_report.json")
    return summary


if __name__ == "__main__":
    run_ioc_extraction()
