"""Parses raw log sources into the normalized event schema used
throughout the pipeline. Currently supports JSON Lines input (as produced
by ingest/log_generator.py); the structure is deliberately kept separate
from the generator so real log sources (syslog, JSON from a SIEM export,
CSV firewall logs, etc.) can be added here without touching detection
or storage code.
"""

import json
from datetime import datetime

REQUIRED_FIELDS = ["timestamp", "event_type", "src_ip", "action"]


def parse_jsonl_file(path):
    """Reads a JSON Lines file and returns a list of normalized event dicts.
    Skips and reports malformed lines rather than crashing the whole run.
    """
    events = []
    skipped = 0
    with open(path, "r") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                _validate(event)
                event["timestamp_dt"] = _parse_timestamp(event["timestamp"])
                events.append(event)
            except (json.JSONDecodeError, ValueError, KeyError) as e:
                skipped += 1
                print(f"  [parser] skipping malformed line {line_no}: {e}")
    if skipped:
        print(f"  [parser] skipped {skipped} malformed line(s) in {path}")
    return events


def _validate(event):
    missing = [f for f in REQUIRED_FIELDS if f not in event]
    if missing:
        raise ValueError(f"missing required fields: {missing}")


def _parse_timestamp(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
