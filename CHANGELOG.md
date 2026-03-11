# Changelog / Dev Notes

Keeping this as a log of what I built and when, mostly for my own reference.

---

## What's working now

- Full pipeline runs end-to-end with `python src/demo_pipeline.py`
- All 7 detection rules fire correctly on simulated logs
- AI triage gives good structured output (finally got the JSON reliable)
- Threat intel enrichment works with AbuseIPDB in live mode
- IR reports generate properly and look professional
- Dashboard shows all the key data

---

## How the project evolved (rough timeline)

**Week 1 — Started with just log parsing**

Started simple. Wrote `log_generator.py` to produce fake syslog entries,
then wrote a basic script to grep for "Failed password" and count occurrences.
Honestly that was all I needed for brute force detection but I wanted to make
it more systematic, like a real SIEM.

**Week 2 — Built the detection rule engine**

Rewrote the detection as proper classes with a rule-per-function structure.
First version of `log_monitor.py` only had 3 rules (brute force, port scan,
new user). Added the rest over a few evenings.

Had a bug where rule 006 (known bad IP) was double-triggering — was checking
both src AND dst in the same loop without tracking which IPs I'd already alerted
on. Fixed with the `seen` set.

**Week 3 — Added threat intel**

Signed up for AbuseIPDB free tier and wrote the API wrapper. The rate limiting
is fine for my use case (1000 checks/day). 

Built the offline database as a fallback so the project works without keys.
Used real data I pulled for those specific IPs to make it accurate.

**Week 4 — The AI triage part**

This took longest. Got the Anthropic API working pretty quickly but the output
was all over the place until I locked down the prompt format.

Key things that helped:
- Telling it to respond ONLY in JSON (not markdown with json block)
- Being specific about every field name and type
- Adding the "SOC analyst with X years experience" role framing
- Including the threat intel data in the context (made verdicts much better)

First version had the AI writing paragraphs of analysis. Good content but not
useful programmatically. Reformatted to structured JSON.

**Week 5 — Report generator and dashboard**

Report generator was straightforward once I had the triage data structured well.
Just markdown templating basically.

Dashboard was fun — first time using the `rich` library. The table rendering
is really clean.

**Ongoing — things to improve**

See the TODO comments scattered through the code. Main things:
- Time-windowed detection for rule 001/002 (currently counts across all logs)
- Real-time file watching for the dashboard
- Sigma rule support
- ELK stack integration

---

## Bugs I hit and fixed

- `ioc_extractor.py`: domain regex was matching version strings like "1.0.2"
  as domains. Fixed by filtering patterns that start with a digit followed by dot.

- `ai_triage.py`: sometimes the API returns the JSON wrapped in ```json fences
  even when you tell it not to. Added a strip step before parsing.

- `threat_intel.py`: wasn't handling request timeouts — would hang if AbuseIPDB
  was slow. Added timeout=5 to the requests call.

- `log_monitor.py`: rule 005 (sudo abuse) was firing on legitimate sudo commands
  like `sudo apt update` because "apt" was in my suspicious terms list by mistake.
  Cleaned up the keyword list.

- `report_generator.py`: KeyError when alert had no `ai_analysis` key (ran it
  before triage had finished). Added .get() with defaults throughout.
