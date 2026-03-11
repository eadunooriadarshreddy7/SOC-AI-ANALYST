"""
packet_analyzer.py

Captures and analyzes network traffic from my home network.

Uses Scapy for the actual packet capture. You need to run this as root
for the capture to work (sudo python src/packet_analyzer.py --live).
I run it on my Raspberry Pi 4 which sits on my home network 24/7.

What it looks for:
  - Top talkers (hosts generating the most traffic)
  - Protocol breakdown (TCP/UDP/DNS)
  - Suspicious ports — I flag anything on 4444, 1337, 6666 etc.
    (these are commonly used by Metasploit and basic backdoors)
  - DNS anomalies — unusually long queries, TXT record queries
  - ARP changes — could indicate ARP spoofing/MITM attack
  - Large outbound transfers that might be data exfiltration

Without root or scapy installed, falls back to simulated packet data
so you can still see how the analysis output looks.

Note: tested this on my Pi with interface 'wlan0', not 'eth0'.
      Change the interface arg if you're on ethernet.
"""

import os
import json
import random
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, ARP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ─── Simulated packet data for demo mode ──────────────────────────────────────

SUSPICIOUS_DOMAINS = [
    "update.windowsupdate-cdn.net",     # Typosquatting
    "a1b2c3d4e5.dnscat.io",             # DNS tunnel
    "malware-cdn.ru",                   # Suspicious TLD
    "34ab.92cd.ef12.pastebin.com",      # Pastebin C2
]

NORMAL_DOMAINS = [
    "google.com", "cloudflare.com", "amazon.com", "netflix.com",
    "reddit.com", "github.com", "stackoverflow.com", "youtube.com"
]

INTERNAL_RANGE = ["192.168.1." + str(i) for i in range(2, 15)]
EXTERNAL_IPS = ["8.8.8.8", "1.1.1.1", "52.86.233.100", "104.26.10.112", "185.220.101.47"]


def simulate_packet_capture(packet_count=100):
    """Generate realistic simulated packet data"""
    print("[*] Scapy not available or not running as root — using simulated capture")
    print("[*] In production: run with sudo python src/packet_analyzer.py --live")
    
    packets_summary = []
    
    for _ in range(packet_count):
        src = random.choice(INTERNAL_RANGE + EXTERNAL_IPS)
        dst = random.choice(INTERNAL_RANGE + EXTERNAL_IPS)
        proto = random.choice(["TCP", "UDP", "DNS"])
        
        if proto == "DNS":
            domain = random.choice(NORMAL_DOMAINS + SUSPICIOUS_DOMAINS[:2])
            packets_summary.append({
                "type": "DNS",
                "src": src,
                "dst": "8.8.8.8",
                "query": domain,
                "suspicious": any(sd in domain for sd in SUSPICIOUS_DOMAINS)
            })
        else:
            port = random.choice([80, 443, 22, 53, 3306, 8080, 4444, 6666])
            size = random.randint(64, 1500)
            packets_summary.append({
                "type": proto,
                "src": src,
                "dst": dst,
                "dst_port": port,
                "size": size,
                "suspicious": port in [4444, 6666]  # Common reverse shell ports
            })
    
    return packets_summary


class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.stats = {
            "total_packets": 0,
            "protocols": defaultdict(int),
            "top_sources": defaultdict(int),
            "top_destinations": defaultdict(int),
            "suspicious_ports": defaultdict(list),
            "dns_queries": [],
            "large_transfers": [],
            "arp_table": {},
        }
        
        # Ports that are suspicious on a home network
        self.suspicious_ports = {
            4444: "Metasploit default",
            6666: "IRC/Botnet",
            1337: "Hacker culture port",
            31337: "Back Orifice",
            8888: "Common backdoor",
            9999: "Common backdoor",
            1234: "Common backdoor",
        }

    def analyze_live(self, interface="eth0", count=200, timeout=30):
        """Capture and analyze live traffic"""
        if not SCAPY_AVAILABLE:
            print("[!] Scapy not installed. Install with: pip install scapy")
            return self.analyze_simulated()
        
        if os.geteuid() != 0:
            print("[!] Packet capture requires root privileges")
            print("    Run: sudo python src/packet_analyzer.py --live")
            return self.analyze_simulated()
        
        print(f"[*] Capturing {count} packets on {interface}...")
        packets = sniff(iface=interface, count=count, timeout=timeout)
        
        for pkt in packets:
            self._process_packet(pkt)
        
        return self._generate_report()

    def _process_packet(self, pkt):
        """Process a single packet"""
        self.stats["total_packets"] += 1
        
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            self.stats["top_sources"][src] += 1
            self.stats["top_destinations"][dst] += 1
            
            # Protocol detection
            if TCP in pkt:
                self.stats["protocols"]["TCP"] += 1
                dport = pkt[TCP].dport
                if dport in self.suspicious_ports:
                    self.stats["suspicious_ports"][dport].append({
                        "src": src, "dst": dst, "note": self.suspicious_ports[dport]
                    })
            
            elif UDP in pkt:
                self.stats["protocols"]["UDP"] += 1
            
            # DNS analysis
            if DNS in pkt and DNSQR in pkt:
                self.stats["protocols"]["DNS"] += 1
                query = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                qtype = pkt[DNSQR].qtype
                self.stats["dns_queries"].append({
                    "src": src,
                    "query": query,
                    "type": qtype,
                    "suspicious": len(query) > 50 or qtype == 16  # TXT = 16
                })
            
            # Large packet detection
            if len(pkt) > 1400:
                self.stats["large_transfers"].append({
                    "src": src, "dst": dst, "size": len(pkt)
                })
        
        # ARP monitoring
        if ARP in pkt:
            self.stats["protocols"]["ARP"] += 1
            arp = pkt[ARP]
            if arp.op == 2:  # ARP reply
                ip = arp.psrc
                mac = arp.hwsrc
                if ip in self.stats["arp_table"]:
                    if self.stats["arp_table"][ip] != mac:
                        print(f"  ⚠️  ARP SPOOFING DETECTED: {ip} has changed MAC to {mac}")
                self.stats["arp_table"][ip] = mac

    def analyze_simulated(self):
        """Analyze simulated packet data"""
        print("\n" + "=" * 60)
        print("  📡 PACKET ANALYSIS — DEMO MODE")
        print("=" * 60)
        
        packets = simulate_packet_capture(150)
        
        for pkt in packets:
            self.stats["total_packets"] += 1
            
            if pkt["type"] == "DNS":
                self.stats["protocols"]["DNS"] += 1
                self.stats["dns_queries"].append({
                    "src": pkt["src"],
                    "query": pkt["query"],
                    "type": 1,
                    "suspicious": pkt["suspicious"]
                })
                self.stats["top_sources"][pkt["src"]] += 1
            
            elif pkt["type"] in ["TCP", "UDP"]:
                self.stats["protocols"][pkt["type"]] += 1
                self.stats["top_sources"][pkt["src"]] += 1
                self.stats["top_destinations"][pkt["dst"]] += 1
                
                if pkt.get("suspicious"):
                    port = pkt.get("dst_port")
                    self.stats["suspicious_ports"][port].append({
                        "src": pkt["src"],
                        "dst": pkt["dst"],
                        "note": self.suspicious_ports.get(port, "Unusual port")
                    })
        
        return self._generate_report()

    def _generate_report(self) -> dict:
        """Generate analysis report"""
        
        # Top 5 sources
        top_src = sorted(
            self.stats["top_sources"].items(),
            key=lambda x: x[1], reverse=True
        )[:5]
        
        # Top 5 destinations
        top_dst = sorted(
            self.stats["top_destinations"].items(),
            key=lambda x: x[1], reverse=True
        )[:5]
        
        # Suspicious DNS
        suspicious_dns = [q for q in self.stats["dns_queries"] if q.get("suspicious")]
        
        report = {
            "capture_time": datetime.now().isoformat(),
            "total_packets": self.stats["total_packets"],
            "protocols": dict(self.stats["protocols"]),
            "top_sources": top_src,
            "top_destinations": top_dst,
            "suspicious_ports": {
                str(port): entries
                for port, entries in self.stats["suspicious_ports"].items()
            },
            "suspicious_dns_queries": suspicious_dns[:10],
            "total_dns_queries": len(self.stats["dns_queries"]),
            "large_transfer_count": len(self.stats["large_transfers"]),
        }
        
        # Print summary
        print(f"\n  📊 CAPTURE SUMMARY")
        print(f"  Total Packets: {report['total_packets']}")
        print(f"\n  Protocol Distribution:")
        for proto, count in sorted(report["protocols"].items(), key=lambda x: x[1], reverse=True):
            bar = "█" * min(int(count / max(report["total_packets"], 1) * 20), 20)
            pct = count / max(report["total_packets"], 1) * 100
            print(f"    {proto:6} {bar:20} {pct:.1f}%")
        
        print(f"\n  Top Talkers:")
        for ip, cnt in top_src[:3]:
            print(f"    {ip:20} {cnt} packets")
        
        if report["suspicious_ports"]:
            print(f"\n  ⚠️  Suspicious Port Activity:")
            for port, entries in report["suspicious_ports"].items():
                print(f"    Port {port}: {len(entries)} connections")
        
        if suspicious_dns:
            print(f"\n  ⚠️  Suspicious DNS Queries: {len(suspicious_dns)}")
            for q in suspicious_dns[:3]:
                print(f"    {q['src']} → {q['query'][:60]}")
        
        # Save
        os.makedirs("logs", exist_ok=True)
        with open("logs/packet_analysis.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Packet analysis saved to logs/packet_analysis.json")
        return report


def run_packet_analysis(live=False, interface="eth0"):
    analyzer = PacketAnalyzer()
    if live and SCAPY_AVAILABLE:
        return analyzer.analyze_live(interface=interface)
    else:
        return analyzer.analyze_simulated()


if __name__ == "__main__":
    import sys
    live = "--live" in sys.argv
    iface = next((sys.argv[sys.argv.index("--iface") + 1]
                  for _ in [None] if "--iface" in sys.argv), "eth0")
    run_packet_analysis(live=live, interface=iface)
