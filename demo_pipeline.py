"""
demo_pipeline.py

Runs the entire SOC pipeline end to end in one go.

Order of operations:
  1. Generate simulated logs (or use real ones from packet_analyzer)
  2. Run SIEM detection rules
  3. Extract IOCs from logs
  4. Enrich with threat intel (AbuseIPDB etc)
  5. AI triage each alert
  6. Packet traffic analysis
  7. Generate IR report
  8. Show dashboard

If you don't have API keys set up, everything still runs in demo mode
with pre-built responses. Add your keys to .env for the real AI triage.

I use this as the main entry point when demoing the project.
"""

import os
import sys
import time
import json

# Make sure imports work from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BANNER = r"""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        🛡️  AI-POWERED SOC ANALYST — HOME LAB DEMO            ║
║                                                               ║
║   Simulating SOC Tier 2 Analyst Workflow with AI Triage      ║
║   MITRE ATT&CK | Threat Intel | Incident Response            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""

STEP_BANNER = lambda n, title: print(f"\n{'='*60}\n  STEP {n}: {title}\n{'='*60}")


def check_env():
    """Check environment and print status"""
    from dotenv import load_dotenv
    load_dotenv()
    
    api_key = os.getenv("ANTHROPIC_API_KEY")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY")
    
    print("\n  📋 Environment Check:")
    print(f"  Claude AI:     {'✅ Connected' if api_key else '⚠️  Demo mode (add key to .env)'}")
    print(f"  AbuseIPDB:     {'✅ Connected' if abuse_key else '⚠️  Demo mode'}")
    print(f"  Python:        ✅ {sys.version.split()[0]}")
    
    try:
        import anthropic
        print(f"  anthropic SDK: ✅ Installed")
    except ImportError:
        print(f"  anthropic SDK: ⚠️  Not installed (pip install anthropic)")
    
    try:
        from faker import Faker
        print(f"  faker:         ✅ Installed")
    except ImportError:
        print(f"  faker:         ❌ Required — run: pip install faker")
        sys.exit(1)


def run_pipeline():
    print(BANNER)
    check_env()
    
    input("\n  Press Enter to start the SOC pipeline demo...\n")
    
    # ─── Step 1: Generate Logs ─────────────────────────────────────────────
    STEP_BANNER(1, "GENERATING SIMULATED HOME NETWORK LOGS")
    print("  Simulating real attack scenarios against home server...")
    time.sleep(0.5)
    
    from log_generator import generate_all_logs
    logs = generate_all_logs()
    time.sleep(0.5)
    
    # ─── Step 2: SIEM Detection ────────────────────────────────────────────
    STEP_BANNER(2, "SIEM DETECTION ENGINE — ANALYZING LOGS")
    print("  Applying detection rules to identify threats...")
    time.sleep(0.5)
    
    from log_monitor import run_monitor
    alerts = run_monitor()
    time.sleep(0.5)
    
    # ─── Step 3: IOC Extraction ────────────────────────────────────────────
    STEP_BANNER(3, "IOC EXTRACTION")
    print("  Extracting Indicators of Compromise from logs...")
    time.sleep(0.5)
    
    from ioc_extractor import run_ioc_extraction
    iocs = run_ioc_extraction()
    time.sleep(0.5)
    
    # ─── Step 4: Threat Intelligence ──────────────────────────────────────
    STEP_BANNER(4, "THREAT INTELLIGENCE ENRICHMENT")
    print("  Looking up IP reputation and threat data...")
    time.sleep(0.5)
    
    from threat_intel import run_threat_intel
    enriched_alerts = run_threat_intel()
    time.sleep(0.5)
    
    # ─── Step 5: AI Triage ────────────────────────────────────────────────
    STEP_BANNER(5, "AI-POWERED ALERT TRIAGE (Claude)")
    print("  Sending alerts to Claude AI for expert analysis...")
    time.sleep(0.5)
    
    from ai_triage import AITriageEngine
    engine = AITriageEngine()
    
    with open("logs/enriched_alerts.json") as f:
        ea = json.load(f)
    
    triage_results = engine.triage_all_alerts(ea)
    time.sleep(0.5)
    
    # ─── Step 6: Packet Analysis ───────────────────────────────────────────
    STEP_BANNER(6, "NETWORK PACKET ANALYSIS")
    print("  Analyzing network traffic patterns...")
    time.sleep(0.5)
    
    from packet_analyzer import run_packet_analysis
    packet_report = run_packet_analysis(live=False)
    time.sleep(0.5)
    
    # ─── Step 7: Incident Report ───────────────────────────────────────────
    STEP_BANNER(7, "GENERATING INCIDENT RESPONSE REPORT")
    print("  Writing AI-assisted incident report...")
    time.sleep(0.5)
    
    from report_generator import run_report_generator
    report = run_report_generator()
    time.sleep(0.5)
    
    # ─── Final Summary ─────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  🎉 PIPELINE COMPLETE")
    print("=" * 60)
    
    critical = sum(1 for a in triage_results
                   if a.get("ai_analysis", {}).get("confirmed_severity") == "CRITICAL")
    tp = sum(1 for a in triage_results
             if a.get("ai_analysis", {}).get("verdict") == "TRUE_POSITIVE")
    escalate = sum(1 for a in triage_results
                   if a.get("ai_analysis", {}).get("escalate"))
    
    print(f"\n  📊 FINAL SOC REPORT:")
    print(f"  ┌─────────────────────────────────────┐")
    print(f"  │  Total Logs Analyzed:   {len(logs):>5}        │")
    print(f"  │  Alerts Detected:       {len(alerts):>5}        │")
    print(f"  │  True Positives:        {tp:>5}        │")
    print(f"  │  Critical Incidents:    {critical:>5}        │")
    print(f"  │  Requires Escalation:   {escalate:>5}        │")
    print(f"  └─────────────────────────────────────┘")
    
    print(f"\n  📁 Output Files Generated:")
    print(f"  • logs/network_logs.json     — Raw simulated logs")
    print(f"  • logs/alerts.json           — SIEM alerts")
    print(f"  • logs/enriched_alerts.json  — Alerts + threat intel")
    print(f"  • logs/triage_results.json   — AI triage analysis")
    print(f"  • logs/ioc_report.json       — Extracted IOCs")
    print(f"  • logs/packet_analysis.json  — Network traffic analysis")
    print(f"  • reports/latest_report.md   — Full IR report")
    
    print(f"\n  📄 View your Incident Report:")
    print(f"  cat reports/latest_report.md\n")


if __name__ == "__main__":
    run_pipeline()
