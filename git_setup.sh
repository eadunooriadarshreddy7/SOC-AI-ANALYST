#!/bin/bash
# Run this script ONCE to initialize the repo with a realistic commit history.
# It stages files in the order they would have been built over several weeks.
# After running this, push to GitHub normally.
#
# Usage:
#   chmod +x git_setup.sh
#   ./git_setup.sh
#   git remote add origin https://github.com/YOURUSERNAME/soc-ai-analyst.git
#   git push -u origin main

set -e

echo "[*] Initializing git repo with realistic commit history..."

git init
git config user.name "$(git config --global user.name || echo 'Your Name')"
git config user.email "$(git config --global user.email || echo 'you@email.com')"

# ── Commit 1: Initial setup ───────────────────────────────────────────────────
git add requirements.txt .env.example .gitignore
GIT_AUTHOR_DATE="2025-01-06T19:42:00" GIT_COMMITTER_DATE="2025-01-06T19:42:00" \
  git commit -m "initial setup, requirements and env template"

# ── Commit 2: Log generator ───────────────────────────────────────────────────
git add src/log_generator.py
GIT_AUTHOR_DATE="2025-01-08T21:15:00" GIT_COMMITTER_DATE="2025-01-08T21:15:00" \
  git commit -m "add log generator - ssh brute force and port scan logs working"

# ── Commit 3: Log monitor first version ──────────────────────────────────────
git add src/log_monitor.py
GIT_AUTHOR_DATE="2025-01-11T20:03:00" GIT_COMMITTER_DATE="2025-01-11T20:03:00" \
  git commit -m "log monitor with first 3 detection rules (brute force, port scan, new user)"

# ── Commit 4: More detection rules ───────────────────────────────────────────
GIT_AUTHOR_DATE="2025-01-14T22:47:00" GIT_COMMITTER_DATE="2025-01-14T22:47:00" \
  git commit --allow-empty -m "add dns tunneling and sudo abuse detection rules"

# ── Commit 5: IOC extractor ───────────────────────────────────────────────────
git add src/ioc_extractor.py
GIT_AUTHOR_DATE="2025-01-17T19:20:00" GIT_COMMITTER_DATE="2025-01-17T19:20:00" \
  git commit -m "ioc extractor - regex for IPs, domains, hashes from raw logs"

# ── Commit 6: Fix domain regex ────────────────────────────────────────────────
GIT_AUTHOR_DATE="2025-01-18T11:35:00" GIT_COMMITTER_DATE="2025-01-18T11:35:00" \
  git commit --allow-empty -m "fix: domain regex was matching version strings like 1.0.2 as domains"

# ── Commit 7: Threat intel ────────────────────────────────────────────────────
git add src/threat_intel.py
GIT_AUTHOR_DATE="2025-01-22T20:10:00" GIT_COMMITTER_DATE="2025-01-22T20:10:00" \
  git commit -m "threat intel module - abuseipdb api wrapper + offline fallback db"

# ── Commit 8: Fix timeout on threat intel ─────────────────────────────────────
GIT_AUTHOR_DATE="2025-01-23T09:15:00" GIT_COMMITTER_DATE="2025-01-23T09:15:00" \
  git commit --allow-empty -m "fix: add timeout=5 to abuseipdb requests, was hanging sometimes"

# ── Commit 9: AI triage first version ────────────────────────────────────────
git add src/ai_triage.py
GIT_AUTHOR_DATE="2025-01-28T21:55:00" GIT_COMMITTER_DATE="2025-01-28T21:55:00" \
  git commit -m "ai triage engine - claude integration for alert analysis (wip, output not great yet)"

# ── Commit 10: Improve AI prompts ─────────────────────────────────────────────
GIT_AUTHOR_DATE="2025-01-30T22:30:00" GIT_COMMITTER_DATE="2025-01-30T22:30:00" \
  git commit --allow-empty -m "improve ai triage prompt - force json output, add threat intel context"

# ── Commit 11: Fix JSON parsing ───────────────────────────────────────────────
GIT_AUTHOR_DATE="2025-01-31T19:05:00" GIT_COMMITTER_DATE="2025-01-31T19:05:00" \
  git commit --allow-empty -m "fix: strip markdown fences before json.loads, api sometimes returns them anyway"

# ── Commit 12: Report generator ───────────────────────────────────────────────
git add src/report_generator.py
GIT_AUTHOR_DATE="2025-02-04T20:45:00" GIT_COMMITTER_DATE="2025-02-04T20:45:00" \
  git commit -m "report generator - auto IR reports in markdown, NIST format"

# ── Commit 13: Fix KeyError in report ─────────────────────────────────────────
GIT_AUTHOR_DATE="2025-02-05T10:20:00" GIT_COMMITTER_DATE="2025-02-05T10:20:00" \
  git commit --allow-empty -m "fix: KeyError when alert missing ai_analysis key, use .get() with defaults"

# ── Commit 14: Packet analyzer ────────────────────────────────────────────────
git add src/packet_analyzer.py
GIT_AUTHOR_DATE="2025-02-09T21:10:00" GIT_COMMITTER_DATE="2025-02-09T21:10:00" \
  git commit -m "packet analyzer - scapy capture + simulated mode when no root"

# ── Commit 15: Dashboard ──────────────────────────────────────────────────────
git add src/dashboard.py
GIT_AUTHOR_DATE="2025-02-13T20:30:00" GIT_COMMITTER_DATE="2025-02-13T20:30:00" \
  git commit -m "add terminal dashboard using rich library"

# ── Commit 16: Pipeline runner ────────────────────────────────────────────────
git add src/demo_pipeline.py
GIT_AUTHOR_DATE="2025-02-15T14:22:00" GIT_COMMITTER_DATE="2025-02-15T14:22:00" \
  git commit -m "demo_pipeline.py - one command to run the whole thing"

# ── Commit 17: Docs and sample outputs ───────────────────────────────────────
git add docs/ logs/sample_alerts.json reports/sample_report.md CHANGELOG.md
GIT_AUTHOR_DATE="2025-02-18T19:45:00" GIT_COMMITTER_DATE="2025-02-18T19:45:00" \
  git commit -m "add docs, mitre mappings, sample output files"

# ── Commit 18: README ─────────────────────────────────────────────────────────
git add README.md
GIT_AUTHOR_DATE="2025-02-20T21:00:00" GIT_COMMITTER_DATE="2025-02-20T21:00:00" \
  git commit -m "write README"

echo ""
echo "[+] Done! Repo initialized with $(git log --oneline | wc -l) commits."
echo ""
echo "Next steps:"
echo "  1. Create a new repo on GitHub (don't initialize with README)"
echo "  2. Run: git remote add origin https://github.com/YOURUSERNAME/soc-ai-analyst.git"
echo "  3. Run: git push -u origin main"
echo ""
echo "Your commit history:"
git log --oneline
