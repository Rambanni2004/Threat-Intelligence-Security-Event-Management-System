"""Loads local threat-intelligence indicators and enriches events with
match info. Optionally augments with live lookups against the free
AbuseIPDB API when ABUSEIPDB_API_KEY is set and --live-intel is passed.
"""

import json
import requests

import config


class IOCFeed:
    def __init__(self, feed_path=config.IOC_FEED_PATH):
        with open(feed_path, "r") as f:
            data = json.load(f)
        self.malicious_ips = {
            entry["ip"]: entry for entry in data.get("malicious_ips", [])
        }
        self.malicious_domains = {
            entry["domain"]: entry for entry in data.get("malicious_domains", [])
        }
        self.last_updated = data.get("last_updated")

    def lookup_ip(self, ip):
        """Returns the local IOC entry for an IP, or None."""
        return self.malicious_ips.get(ip)

    def lookup_domain(self, domain):
        return self.malicious_domains.get(domain)


_abuseipdb_cache = {}


def lookup_ip_live(ip):
    """Query AbuseIPDB for live IP reputation. Requires ABUSEIPDB_API_KEY.
    Results are cached in-process to avoid repeat lookups / rate limits.
    Returns a dict like the local IOC format, or None if not found/failed.
    """
    if not config.ABUSEIPDB_API_KEY:
        return None
    if ip in _abuseipdb_cache:
        return _abuseipdb_cache[ip]

    try:
        resp = requests.get(
            config.ABUSEIPDB_URL,
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        result = None
        if score and score >= 25:
            result = {
                "ip": ip,
                "category": "abuseipdb-reported",
                "confidence": score,
                "source": "AbuseIPDB",
            }
        _abuseipdb_cache[ip] = result
        return result
    except requests.RequestException as e:
        print(f"  [intel] AbuseIPDB lookup failed for {ip}: {e}")
        return None


def enrich_events(events, ioc_feed, use_live_intel=False):
    """Attaches a `threat_intel` field to each event: None if clean,
    otherwise the matching IOC entry (local feed takes priority over
    live lookups since it's free and instant).
    """
    for event in events:
        ip = event.get("src_ip")
        match = ioc_feed.lookup_ip(ip) if ip else None
        if not match and use_live_intel and ip:
            match = lookup_ip_live(ip)
        event["threat_intel"] = match
    return events
