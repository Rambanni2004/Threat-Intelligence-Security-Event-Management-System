"""CLI entry point that runs the full pipeline:
ingest -> threat-intel enrichment -> detection rules -> alert storage.

Usage:
    python run_pipeline.py --source data/sample_logs.jsonl
    python run_pipeline.py --generate 500
    python run_pipeline.py --source data/sample_logs.jsonl --live-intel
    python run_pipeline.py --source data/sample_logs.jsonl --reset
"""

import argparse
import sys

import config
from ingest.parsers import parse_jsonl_file
from ingest.log_generator import generate as generate_events
from intel.ioc_feed import IOCFeed, enrich_events
from detection.rules import run_all_rules
from storage import db


def main():
    parser = argparse.ArgumentParser(description="Run the threat-intel SIEM pipeline.")
    parser.add_argument("--source", help="Path to a JSON Lines log file to ingest.")
    parser.add_argument("--generate", type=int, metavar="N",
                         help="Generate N synthetic benign events (plus injected attacks) instead of reading --source.")
    parser.add_argument("--live-intel", action="store_true",
                         help="Also query AbuseIPDB for IPs not found in the local IOC feed (requires ABUSEIPDB_API_KEY).")
    parser.add_argument("--reset", action="store_true",
                         help="Clear existing alerts from the database before running.")
    args = parser.parse_args()

    if not args.source and not args.generate:
        print("Provide either --source <file> or --generate <N>. See --help.")
        sys.exit(1)

    db.init_db()
    if args.reset:
        db.clear_alerts()
        print("Cleared existing alerts.")

    print("Step 1/4: Ingesting events...")
    if args.generate:
        events = generate_events(count=args.generate, seed=None, out_path=config.SAMPLE_LOGS_PATH)
        print(f"  Generated {len(events)} events -> {config.SAMPLE_LOGS_PATH}")
        events = parse_jsonl_file(config.SAMPLE_LOGS_PATH)
    else:
        events = parse_jsonl_file(args.source)
    print(f"  Loaded {len(events)} normalized events.")

    print("Step 2/4: Enriching with threat intelligence...")
    ioc_feed = IOCFeed()
    events = enrich_events(events, ioc_feed, use_live_intel=args.live_intel)
    flagged = sum(1 for e in events if e.get("threat_intel"))
    print(f"  {flagged} event(s) matched a known-malicious indicator.")

    print("Step 3/4: Running detection rules...")
    alerts = run_all_rules(events)
    print(f"  {len(alerts)} alert(s) generated.")

    print("Step 4/4: Storing alerts...")
    db.insert_alerts(alerts)
    print(f"  Stored in {config.DB_PATH}")

    print("\nSummary:")
    for a in alerts:
        print(f"  [{a['severity'].upper():8}] {a['rule']:20} {a['title']}")

    print("\nDone. Run `python app.py` and open http://localhost:5000 to view the dashboard.")


if __name__ == "__main__":
    main()
