"""Generates realistic synthetic security events, with several attack
patterns deliberately injected so every detection rule has something to
catch. Output is JSON Lines, matching the schema in ingest/parsers.py.

Event schema (normalized):
{
    "timestamp": ISO-8601 str,
    "event_type": "auth" | "network" | "web",
    "src_ip": str,
    "dst_ip": str,
    "dst_port": int,
    "user": str | null,
    "action": str,          # login_success, login_failure, connection, http_request
    "country": str | null,  # geo of the source, for auth events
}
"""

import json
import random
from datetime import datetime, timedelta, timezone

BENIGN_IPS = [
    "10.0.0.15", "10.0.0.42", "192.168.1.20", "192.168.1.55",
    "172.16.4.9", "203.0.113.7", "203.0.113.44",
]
USERS = ["alice", "bob", "carol", "dave", "erin", "frank"]
COUNTRIES = ["IN", "US", "GB", "DE", "SG"]
WEB_PORTS = [80, 443]
COMMON_PORTS = [22, 80, 443, 3306, 5432, 8080, 8443, 21, 25, 3389]

# Pulled from intel/sample_iocs.json so the generator's "bad" traffic
# actually matches what the enrichment step will flag.
MALICIOUS_IPS = [
    "185.220.101.13", "45.155.204.77", "194.26.29.150",
    "103.99.0.203", "91.240.118.192", "198.98.51.100",
]


def iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def gen_benign_traffic(start, count):
    events = []
    t = start
    for _ in range(count):
        t += timedelta(seconds=random.randint(5, 120))
        src = random.choice(BENIGN_IPS)
        user = random.choice(USERS)
        kind = random.choice(["auth", "network", "web"])
        if kind == "auth":
            events.append({
                "timestamp": iso(t),
                "event_type": "auth",
                "src_ip": src,
                "dst_ip": "10.0.0.1",
                "dst_port": 22,
                "user": user,
                "action": "login_success",
                "country": "IN",
            })
        elif kind == "network":
            events.append({
                "timestamp": iso(t),
                "event_type": "network",
                "src_ip": src,
                "dst_ip": "10.0.0.5",
                "dst_port": random.choice(WEB_PORTS),
                "user": None,
                "action": "connection",
                "country": None,
            })
        else:
            events.append({
                "timestamp": iso(t),
                "event_type": "web",
                "src_ip": src,
                "dst_ip": "10.0.0.5",
                "dst_port": 443,
                "user": user,
                "action": "http_request",
                "country": "IN",
            })
    return events, t


def inject_brute_force(start_time, target_user="alice", attempts=8):
    """Many failed logins from one external IP against one account."""
    attacker_ip = "103.99.0.203"  # matches sample_iocs.json
    events = []
    t = start_time
    for i in range(attempts):
        t += timedelta(seconds=random.randint(2, 8))
        events.append({
            "timestamp": iso(t),
            "event_type": "auth",
            "src_ip": attacker_ip,
            "dst_ip": "10.0.0.1",
            "dst_port": 22,
            "user": target_user,
            "action": "login_failure",
            "country": "RU",
        })
    # occasionally the attacker gets in on the last try
    t += timedelta(seconds=3)
    events.append({
        "timestamp": iso(t),
        "event_type": "auth",
        "src_ip": attacker_ip,
        "dst_ip": "10.0.0.1",
        "dst_port": 22,
        "user": target_user,
        "action": "login_success",
        "country": "RU",
    })
    return events, t


def inject_port_scan(start_time):
    """One source IP probing many destination ports quickly."""
    scanner_ip = "45.155.204.77"  # matches sample_iocs.json
    events = []
    t = start_time
    ports = random.sample(COMMON_PORTS, k=min(9, len(COMMON_PORTS)))
    for port in ports:
        t += timedelta(seconds=random.randint(1, 4))
        events.append({
            "timestamp": iso(t),
            "event_type": "network",
            "src_ip": scanner_ip,
            "dst_ip": "10.0.0.5",
            "dst_port": port,
            "user": None,
            "action": "connection",
            "country": None,
        })
    return events, t


def inject_blacklisted_contact(start_time):
    """A single connection from a known-malicious IP (e.g. C2 callback)."""
    bad_ip = "194.26.29.150"  # matches sample_iocs.json, category c2-server
    t = start_time + timedelta(seconds=random.randint(5, 30))
    event = {
        "timestamp": iso(t),
        "event_type": "network",
        "src_ip": bad_ip,
        "dst_ip": "10.0.0.5",
        "dst_port": 443,
        "user": None,
        "action": "connection",
        "country": None,
    }
    return [event], t


def inject_impossible_travel(start_time, user="bob"):
    """Same user logging in from two distant countries within minutes."""
    t1 = start_time + timedelta(seconds=10)
    t2 = t1 + timedelta(minutes=4)  # too soon to physically travel IN -> US
    events = [
        {
            "timestamp": iso(t1),
            "event_type": "auth",
            "src_ip": "203.0.113.7",
            "dst_ip": "10.0.0.1",
            "dst_port": 22,
            "user": user,
            "action": "login_success",
            "country": "IN",
        },
        {
            "timestamp": iso(t2),
            "event_type": "auth",
            "src_ip": "91.240.118.192",  # malicious IP, bonus overlap
            "dst_ip": "10.0.0.1",
            "dst_port": 22,
            "user": user,
            "action": "login_success",
            "country": "US",
        },
    ]
    return events, t2


def generate(count=500, seed=None, out_path=None):
    """Generate `count` benign events plus a fixed set of injected attacks,
    shuffle-merge them in timestamp order, and optionally write to out_path
    as JSON Lines. Returns the list of events either way.
    """
    if seed is not None:
        random.seed(seed)

    start = datetime.now(timezone.utc) - timedelta(hours=2)
    all_events = []

    benign, t = gen_benign_traffic(start, count)
    all_events.extend(benign)

    bf_events, t = inject_brute_force(start + timedelta(minutes=20))
    all_events.extend(bf_events)

    ps_events, t = inject_port_scan(start + timedelta(minutes=40))
    all_events.extend(ps_events)

    bl_events, t = inject_blacklisted_contact(start + timedelta(minutes=55))
    all_events.extend(bl_events)

    it_events, t = inject_impossible_travel(start + timedelta(minutes=70))
    all_events.extend(it_events)

    all_events.sort(key=lambda e: e["timestamp"])

    if out_path:
        with open(out_path, "w") as f:
            for e in all_events:
                f.write(json.dumps(e) + "\n")

    return all_events


if __name__ == "__main__":
    import sys
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 500
    events = generate(count=n, seed=42, out_path="data/sample_logs.jsonl")
    print(f"Generated {len(events)} events -> data/sample_logs.jsonl")
