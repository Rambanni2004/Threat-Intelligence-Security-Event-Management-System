# Threat Intelligence & Security Event Management System

A lightweight SIEM (Security Information and Event Management) prototype that
ingests security event logs, enriches them with threat-intelligence data
(known-malicious IPs, domains, and hashes), correlates events using a rules
engine, and surfaces prioritized alerts through a web dashboard.

Built to demonstrate core security engineering concepts: log parsing,
IOC (Indicator of Compromise) matching, detection-rule design, alert
scoring, and security data visualization — without depending on any paid
services. Everything runs locally with sample data out of the box.

## Features

- **Log ingestion** — parses authentication logs, firewall/network logs,
  and web server logs from JSON Lines files (`data/sample_logs.jsonl`),
  or generates realistic synthetic traffic for demos.
- **Threat intel enrichment** — checks source IPs/domains against a local
  IOC feed (`intel/sample_iocs.json`). Optional live enrichment via the
  free [AbuseIPDB](https://www.abuseipdb.com/) API if you provide an API key.
- **Detection rules engine** — pluggable rules, shipped with:
  - Brute-force login detection (N failed logins from one IP in a window)
  - Blacklisted IP / known-bad indicator match
  - Port scan detection (many distinct destination ports from one source)
  - Impossible travel (same account, two countries, too little time between)
- **Alert storage & scoring** — alerts persisted in SQLite with a
  severity score (low/medium/high/critical) and status (open/acknowledged/closed).
- **Dashboard** — Flask + Chart.js web UI showing alert volume over time,
  top offending IPs, severity breakdown, and a filterable alert table.

## Architecture

```
                 ┌─────────────────┐
 sample_logs ──▶ │  Ingest/Parsers  │
 (or generator)  └────────┬─────────┘
                          │ normalized events
                          ▼
                 ┌─────────────────┐      ┌───────────────────┐
                 │  Threat Intel    │◀────▶│ intel/sample_iocs │
                 │  Enrichment      │      │ (or AbuseIPDB API)│
                 └────────┬─────────┘      └───────────────────┘
                          │ enriched events
                          ▼
                 ┌─────────────────┐
                 │ Detection Rules  │
                 │     Engine       │
                 └────────┬─────────┘
                          │ alerts
                          ▼
                 ┌─────────────────┐      ┌───────────────────┐
                 │  SQLite Storage  │◀────▶│   Flask Dashboard  │
                 └─────────────────┘      └───────────────────┘
```

## Project layout

```
threat-intel-siem/
├── app.py                  # Flask dashboard entry point
├── run_pipeline.py         # CLI: ingest -> enrich -> detect -> store
├── config.py                # Central configuration
├── ingest/
│   ├── log_generator.py     # Synthetic event generator for demos
│   └── parsers.py           # Normalizes raw log lines into events
├── intel/
│   ├── ioc_feed.py          # Loads local IOCs + optional AbuseIPDB lookups
│   └── sample_iocs.json     # Sample malicious IP/domain indicators
├── detection/
│   └── rules.py             # Detection rule implementations
├── storage/
│   └── db.py                 # SQLite schema + read/write helpers
├── templates/                # Dashboard HTML (Jinja2)
├── static/style.css          # Dashboard styling
├── data/sample_logs.jsonl    # Sample raw security events
└── tests/test_rules.py       # Unit tests for detection rules
```

## Getting started

```bash
git clone https://github.com/<your-username>/threat-intel-siem.git
cd threat-intel-siem
python -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt

# 1. Run the pipeline once against the bundled sample data
python run_pipeline.py --source data/sample_logs.jsonl

# 2. Or generate fresh synthetic traffic (includes injected attacks) and run it
python run_pipeline.py --generate 500

# 3. Launch the dashboard
python app.py
# then open http://localhost:5000
```

### Optional: live threat-intel enrichment

By default the system matches against the bundled `intel/sample_iocs.json`
IOC list, which is enough to see every detection rule fire against the
sample data. To additionally query the free AbuseIPDB API for real-world
IP reputation:

```bash
export ABUSEIPDB_API_KEY="your_api_key_here"
python run_pipeline.py --source data/sample_logs.jsonl --live-intel
```

## Running tests

```bash
python -m pytest tests/
```

## Why this project

This project was built to demonstrate practical security engineering
skills relevant to Threat Intelligence & Security Event Management roles:
log normalization, IOC-based enrichment, writing and testing detection
logic, and presenting security findings in a way analysts can act on.

## Possible extensions

- Ingest real log sources (syslog, CloudTrail, Windows Event Log via Winlogbeat)
- Add MITRE ATT&CK technique tagging to each detection rule
- Ship alerts to Slack/email/webhook
- Add a case-management workflow (assign, comment, close with resolution)
- Swap SQLite for Postgres for multi-user deployments

## License

MIT — see `LICENSE`.
