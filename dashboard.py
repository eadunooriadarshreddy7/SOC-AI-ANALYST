"""
dashboard.py

Terminal SOC dashboard — shows the alert queue and triage results
in a readable format.

Uses the 'rich' library for the nice tables and colors. First time using
rich for a project, it's pretty great once you get used to the API.

The dashboard reads from whatever JSON files are available in /logs.
If you've run the full pipeline, it shows everything. If you've only
run part of it, it shows what it has.

Run after demo_pipeline.py:
    python src/dashboard.py

TODO: make this actually live-updating (watch the log files for changes)
TODO: add a way to mark alerts as reviewed from the dashboard itself
"""

import json
import os
import sys
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.text import Text
    from rich.layout import Layout
    from rich.live import Live
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None

SEVERITY_STYLES = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold blue",
    "LOW":      "bold green",
    "INFO":     "dim",
}

VERDICT_STYLES = {
    "TRUE_POSITIVE":      "bold red",
    "FALSE_POSITIVE":     "bold green",
    "NEEDS_INVESTIGATION": "bold yellow",
}


def load_data():
    """Load all available data files"""
    data = {}
    
    files = {
        "triage":   "logs/triage_results.json",
        "alerts":   "logs/alerts.json",
        "iocs":     "logs/ioc_report.json",
        "packets":  "logs/packet_analysis.json",
    }
    
    for key, path in files.items():
        try:
            with open(path) as f:
                data[key] = json.load(f)
        except FileNotFoundError:
            data[key] = None
    
    return data


def render_dashboard_rich(data: dict):
    """Render full dashboard using Rich library"""
    
    alerts = data.get("triage") or data.get("alerts") or []
    iocs = data.get("iocs")
    packets = data.get("packets")
    
    # ─── Header ────────────────────────────────────────────────────────────
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    console.print(Panel(
        f"[bold cyan]🛡️  AI-POWERED SOC ANALYST DASHBOARD[/bold cyan]\n"
        f"[dim]Home Network Security Operations Center | {now}[/dim]",
        box=box.DOUBLE_EDGE,
        border_style="cyan"
    ))
    
    # ─── Metrics Row ───────────────────────────────────────────────────────
    if alerts:
        total = len(alerts)
        critical = sum(1 for a in alerts if a.get("ai_analysis", a).get("confirmed_severity", a.get("severity")) == "CRITICAL")
        tp = sum(1 for a in alerts if a.get("ai_analysis", {}).get("verdict") == "TRUE_POSITIVE")
        escalate = sum(1 for a in alerts if a.get("ai_analysis", {}).get("escalate"))
        
        metrics = [
            Panel(f"[bold white]{total}[/bold white]\n[dim]Total Alerts[/dim]", border_style="blue"),
            Panel(f"[bold red]{critical}[/bold red]\n[dim]Critical[/dim]", border_style="red"),
            Panel(f"[bold green]{tp}[/bold green]\n[dim]True Positives[/dim]", border_style="green"),
            Panel(f"[bold yellow]{escalate}[/bold yellow]\n[dim]Need Escalation[/dim]", border_style="yellow"),
        ]
        console.print(Columns(metrics))
    
    # ─── Alert Queue ───────────────────────────────────────────────────────
    console.print("\n[bold]📋 ALERT QUEUE[/bold]")
    
    alert_table = Table(
        show_header=True, header_style="bold cyan",
        box=box.ROUNDED, border_style="dim"
    )
    alert_table.add_column("Alert ID", style="dim", width=18)
    alert_table.add_column("Rule", width=28)
    alert_table.add_column("Severity", width=10)
    alert_table.add_column("Source IP", width=18)
    alert_table.add_column("MITRE", width=12)
    alert_table.add_column("Verdict", width=20)
    alert_table.add_column("Escalate", width=9)
    
    for alert in alerts:
        ai = alert.get("ai_analysis", {})
        sev = ai.get("confirmed_severity", alert.get("severity", "UNKNOWN"))
        verdict = ai.get("verdict", "PENDING")
        sev_style = SEVERITY_STYLES.get(sev, "")
        verdict_style = VERDICT_STYLES.get(verdict, "dim")
        
        mitre = ai.get("mitre_technique", {}).get("tid", alert.get("mitre_tid", "N/A"))
        escalate = "🚨 YES" if ai.get("escalate") else "No"
        esc_style = "bold red" if ai.get("escalate") else "dim"
        
        alert_table.add_row(
            alert.get("alert_id", "N/A"),
            alert.get("rule_name", "Unknown")[:27],
            Text(sev, style=sev_style),
            alert.get("src_ip", "N/A"),
            mitre,
            Text(verdict, style=verdict_style),
            Text(escalate, style=esc_style),
        )
    
    console.print(alert_table)
    
    # ─── Top Threats Detail ────────────────────────────────────────────────
    critical_alerts = [a for a in alerts
                       if a.get("ai_analysis", {}).get("confirmed_severity") == "CRITICAL"]
    
    if critical_alerts:
        console.print("\n[bold red]🔴 CRITICAL INCIDENTS — IMMEDIATE ACTION REQUIRED[/bold red]")
        for alert in critical_alerts[:3]:
            ai = alert.get("ai_analysis", {})
            intel = alert.get("threat_intel", {})
            
            actions_text = "\n".join(
                f"  {i+1}. {a}" for i, a in enumerate(ai.get("immediate_actions", [])[:3])
            )
            
            console.print(Panel(
                f"[bold]{alert.get('rule_name')}[/bold]\n"
                f"[dim]IP: {alert.get('src_ip')} | Confidence: {ai.get('confidence', 0)}%[/dim]\n\n"
                f"[yellow]{ai.get('attack_summary', '')}[/yellow]\n\n"
                f"[bold]Actions:[/bold]\n{actions_text}",
                border_style="red",
                title=f"[red]{alert.get('alert_id')}[/red]"
            ))
    
    # ─── IOC Summary ───────────────────────────────────────────────────────
    if iocs:
        console.print("\n[bold]🔬 INDICATORS OF COMPROMISE[/bold]")
        
        ioc_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
        ioc_table.add_column("Type", width=15)
        ioc_table.add_column("Indicator", width=35)
        ioc_table.add_column("Frequency", width=12)
        
        for category in ["external_ips", "domains"]:
            items = iocs.get("iocs", {}).get(category, [])
            for item in items[:4]:
                ioc_table.add_row(
                    Text(item.get("type", category), style="bold"),
                    item.get("indicator", ""),
                    str(item.get("count", 0)),
                )
        
        console.print(ioc_table)
    
    # ─── Packet Analysis ───────────────────────────────────────────────────
    if packets:
        console.print("\n[bold]📡 NETWORK TRAFFIC ANALYSIS[/bold]")
        
        proto_table = Table(show_header=True, header_style="bold blue", box=box.SIMPLE)
        proto_table.add_column("Protocol", width=10)
        proto_table.add_column("Packets", width=10)
        proto_table.add_column("% Traffic", width=12)
        
        total_pkts = packets.get("total_packets", 1)
        for proto, count in sorted(packets.get("protocols", {}).items(),
                                    key=lambda x: x[1], reverse=True):
            pct = count / total_pkts * 100
            bar = "▓" * int(pct / 5)
            proto_table.add_row(proto, str(count), f"{bar} {pct:.1f}%")
        
        console.print(proto_table)
        
        if packets.get("suspicious_ports"):
            console.print("[bold red]  ⚠️  Suspicious port activity detected![/bold red]")
            for port, entries in packets["suspicious_ports"].items():
                note = entries[0].get("note", "Unknown") if entries else "Unknown"
                console.print(f"  Port [bold]{port}[/bold]: {len(entries)} connections — {note}")
    
    # ─── Footer ────────────────────────────────────────────────────────────
    console.print(Panel(
        "[dim]AI Engine: Claude (Anthropic) | Detection: Custom SIEM Rules | "
        "Framework: MITRE ATT&CK | Report: reports/latest_report.md[/dim]",
        border_style="dim"
    ))


def render_dashboard_basic(data: dict):
    """Fallback plain text dashboard"""
    alerts = data.get("triage") or data.get("alerts") or []
    
    print("\n" + "=" * 70)
    print("  🛡️  SOC ANALYST DASHBOARD")
    print("=" * 70)
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total Alerts: {len(alerts)}")
    
    for alert in alerts:
        ai = alert.get("ai_analysis", {})
        sev = ai.get("confirmed_severity", alert.get("severity", "?"))
        verdict = ai.get("verdict", "PENDING")
        print(f"\n  [{sev:8}] {alert.get('rule_name', 'Unknown')}")
        print(f"           IP: {alert.get('src_ip')} | {verdict}")
        print(f"           MITRE: {alert.get('mitre_tid')}")
        if ai.get("escalate"):
            print(f"           ⚠️  ESCALATION NEEDED")


def run_dashboard():
    """Main entry point for dashboard"""
    print("[*] Loading SOC dashboard data...")
    data = load_data()
    
    if not any(data.values()):
        print("[!] No data found. Run the pipeline first:")
        print("    python src/demo_pipeline.py")
        return
    
    if RICH_AVAILABLE:
        render_dashboard_rich(data)
    else:
        print("[*] Rich library not installed. Install for better display: pip install rich")
        render_dashboard_basic(data)


if __name__ == "__main__":
    run_dashboard()
