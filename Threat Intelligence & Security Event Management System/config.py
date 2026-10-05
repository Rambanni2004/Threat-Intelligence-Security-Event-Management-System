"""Central configuration for the Threat Intel & SIEM system."""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.path.join(BASE_DIR, "storage", "siem.db")

SAMPLE_LOGS_PATH = os.path.join(BASE_DIR, "data", "sample_logs.jsonl")
IOC_FEED_PATH = os.path.join(BASE_DIR, "intel", "sample_iocs.json")

# Detection rule thresholds — tune these for your environment
BRUTE_FORCE_FAILED_ATTEMPTS = 5     # failed logins ...
BRUTE_FORCE_WINDOW_SECONDS = 300    # ... within this many seconds
PORT_SCAN_DISTINCT_PORTS = 8        # distinct ports ...
PORT_SCAN_WINDOW_SECONDS = 60       # ... within this many seconds
IMPOSSIBLE_TRAVEL_MAX_KMH = 900     # faster than this between two logins = impossible

# Optional live threat-intel enrichment (AbuseIPDB free tier)
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

SEVERITY_ORDER = ["low", "medium", "high", "critical"]
