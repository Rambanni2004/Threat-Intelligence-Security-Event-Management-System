"""Detection rules engine.

Each rule takes the full list of enriched, normalized events and returns
a list of alert dicts. Rules are intentionally independent and stateless
functions so new ones can be added without touching existing logic —
see `run_all_rules` at the bottom for the registry.

Alert schema:
{
    "rule": str,             # machine name, e.g. "brute_force"
    "severity": str,         # low | medium | high | critical
    "title": str,            # short human-readable summary
    "description": str,      # longer explanation with specifics
    "src_ip": str,
    "user": str | None,
    "timestamp": str,        # ISO-8601 timestamp of the triggering event
    "evidence": dict,        # rule-specific supporting data
}
"""

from collections import defaultdict
from datetime import timedelta

import config

# Rough country-pair distances (km) for a small, illustrative impossible
# travel check. Not exhaustive — a real system would use a geo-IP distance
# calculation (e.g. haversine over lat/long).
_COUNTRY_DISTANCE_KM = {
    frozenset({"IN", "US"}): 13000,
    frozenset({"IN", "GB"}): 8000,
    frozenset({"IN", "RU"}): 5000,
    frozenset({"IN", "DE"}): 6000,
    frozenset({"IN", "SG"}): 2900,
    frozenset({"US", "GB"}): 5500,
    frozenset({"US", "RU"}): 8000,
}


def detect_brute_force(events):
    alerts = []
    auth_events = [e for e in events if e["event_type"] == "auth"]
    by_key = defaultdict(list)
    for e in auth_events:
        by_key[(e["src_ip"], e.get("user"))].append(e)

    for (src_ip, user), evs in by_key.items():
        evs = sorted(evs, key=lambda e: e["timestamp_dt"])
        failures = [e for e in evs if e["action"] == "login_failure"]

        window = timedelta(seconds=config.BRUTE_FORCE_WINDOW_SECONDS)
        i = 0
        for j in range(len(failures)):
            while failures[j]["timestamp_dt"] - failures[i]["timestamp_dt"] > window:
                i += 1
            count = j - i + 1
            if count >= config.BRUTE_FORCE_FAILED_ATTEMPTS:
                trigger = failures[j]
                followed_by_success = any(
                    e["action"] == "login_success" and e["timestamp_dt"] >= trigger["timestamp_dt"]
                    for e in evs
                )
                alerts.append({
                    "rule": "brute_force",
                    "severity": "critical" if followed_by_success else "high",
                    "title": f"Brute-force login attempts against '{user}'",
                    "description": (
                        f"{count} failed login attempts from {src_ip} targeting "
                        f"user '{user}' within {config.BRUTE_FORCE_WINDOW_SECONDS}s."
                        + (" A successful login followed — account may be compromised."
                           if followed_by_success else "")
                    ),
                    "src_ip": src_ip,
                    "user": user,
                    "timestamp": trigger["timestamp"],
                    "evidence": {"failed_attempts": count, "followed_by_success": followed_by_success},
                })
                break  # one alert per (src_ip, user) is enough for the demo
    return alerts


def detect_port_scan(events):
    alerts = []
    net_events = [e for e in events if e["event_type"] == "network" and e["action"] == "connection"]
    by_src = defaultdict(list)
    for e in net_events:
        by_src[e["src_ip"]].append(e)

    window = timedelta(seconds=config.PORT_SCAN_WINDOW_SECONDS)
    for src_ip, evs in by_src.items():
        evs = sorted(evs, key=lambda e: e["timestamp_dt"])
        i = 0
        for j in range(len(evs)):
            while evs[j]["timestamp_dt"] - evs[i]["timestamp_dt"] > window:
                i += 1
            window_events = evs[i:j + 1]
            distinct_ports = {e["dst_port"] for e in window_events}
            if len(distinct_ports) >= config.PORT_SCAN_DISTINCT_PORTS:
                alerts.append({
                    "rule": "port_scan",
                    "severity": "high",
                    "title": f"Possible port scan from {src_ip}",
                    "description": (
                        f"{src_ip} probed {len(distinct_ports)} distinct ports "
                        f"against {window_events[-1]['dst_ip']} within "
                        f"{config.PORT_SCAN_WINDOW_SECONDS}s: {sorted(distinct_ports)}."
                    ),
                    "src_ip": src_ip,
                    "user": None,
                    "timestamp": evs[j]["timestamp"],
                    "evidence": {"distinct_ports": sorted(distinct_ports)},
                })
                break
    return alerts


def detect_blacklisted_ip(events):
    alerts = []
    seen_ips = set()
    for e in events:
        intel = e.get("threat_intel")
        if not intel:
            continue
        ip = e["src_ip"]
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        confidence = intel.get("confidence", 50)
        severity = "critical" if confidence >= 90 else "high" if confidence >= 70 else "medium"
        alerts.append({
            "rule": "blacklisted_ip",
            "severity": severity,
            "title": f"Traffic from known-malicious IP ({intel.get('category', 'unknown')})",
            "description": (
                f"{ip} matched threat-intel indicator category "
                f"'{intel.get('category', 'unknown')}' (confidence {confidence}, "
                f"source: {intel.get('source', 'unknown')})."
            ),
            "src_ip": ip,
            "user": e.get("user"),
            "timestamp": e["timestamp"],
            "evidence": {"ioc": intel},
        })
    return alerts


def detect_impossible_travel(events):
    alerts = []
    auth_success = [
        e for e in events
        if e["event_type"] == "auth" and e["action"] == "login_success" and e.get("user") and e.get("country")
    ]
    by_user = defaultdict(list)
    for e in auth_success:
        by_user[e["user"]].append(e)

    for user, evs in by_user.items():
        evs = sorted(evs, key=lambda e: e["timestamp_dt"])
        for a, b in zip(evs, evs[1:]):
            if a["country"] == b["country"]:
                continue
            delta_hours = (b["timestamp_dt"] - a["timestamp_dt"]).total_seconds() / 3600
            if delta_hours <= 0:
                continue
            distance = _COUNTRY_DISTANCE_KM.get(frozenset({a["country"], b["country"]}), 5000)
            required_speed = distance / delta_hours
            if required_speed > config.IMPOSSIBLE_TRAVEL_MAX_KMH:
                alerts.append({
                    "rule": "impossible_travel",
                    "severity": "critical",
                    "title": f"Impossible travel for user '{user}'",
                    "description": (
                        f"'{user}' logged in from {a['country']} ({a['src_ip']}) then from "
                        f"{b['country']} ({b['src_ip']}) only "
                        f"{delta_hours * 60:.1f} minutes later — implies ~{required_speed:.0f} km/h "
                        "travel, which is not physically possible."
                    ),
                    "src_ip": b["src_ip"],
                    "user": user,
                    "timestamp": b["timestamp"],
                    "evidence": {
                        "first_login": {"country": a["country"], "ip": a["src_ip"], "time": a["timestamp"]},
                        "second_login": {"country": b["country"], "ip": b["src_ip"], "time": b["timestamp"]},
                        "implied_speed_kmh": round(required_speed, 1),
                    },
                })
    return alerts


# Registry of all rules — add new rules here to have them picked up
# automatically by run_pipeline.py.
ALL_RULES = [
    detect_brute_force,
    detect_port_scan,
    detect_blacklisted_ip,
    detect_impossible_travel,
]


def run_all_rules(events):
    alerts = []
    for rule_fn in ALL_RULES:
        alerts.extend(rule_fn(events))
    alerts.sort(key=lambda a: config.SEVERITY_ORDER.index(a["severity"]), reverse=True)
    return alerts
