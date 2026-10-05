"""Unit tests for the detection rules engine. Run with:
    python -m pytest tests/
"""

import sys
import os
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.rules import (
    detect_brute_force,
    detect_port_scan,
    detect_blacklisted_ip,
    detect_impossible_travel,
)


def _event(**kwargs):
    """Builds a minimal normalized event dict with sensible defaults."""
    base = {
        "timestamp": "2026-01-01T00:00:00Z",
        "event_type": "auth",
        "src_ip": "1.2.3.4",
        "dst_ip": "10.0.0.1",
        "dst_port": 22,
        "user": None,
        "action": "login_success",
        "country": None,
        "threat_intel": None,
    }
    base.update(kwargs)
    base["timestamp_dt"] = datetime.strptime(base["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
    return base


def _ts(base, seconds):
    dt = datetime.strptime(base, "%Y-%m-%dT%H:%M:%SZ") + timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_brute_force_triggers_on_repeated_failures():
    base = "2026-01-01T00:00:00Z"
    events = [
        _event(timestamp=_ts(base, i * 10), user="alice", action="login_failure")
        for i in range(6)
    ]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "brute_force"
    assert alerts[0]["evidence"]["failed_attempts"] >= 5


def test_brute_force_does_not_trigger_below_threshold():
    base = "2026-01-01T00:00:00Z"
    events = [
        _event(timestamp=_ts(base, i * 10), user="alice", action="login_failure")
        for i in range(3)
    ]
    alerts = detect_brute_force(events)
    assert alerts == []


def test_port_scan_triggers_on_many_distinct_ports():
    base = "2026-01-01T00:00:00Z"
    events = [
        _event(
            timestamp=_ts(base, i * 2), event_type="network", action="connection",
            dst_port=1000 + i,
        )
        for i in range(9)
    ]
    alerts = detect_port_scan(events)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "port_scan"


def test_port_scan_ignores_few_ports():
    base = "2026-01-01T00:00:00Z"
    events = [
        _event(
            timestamp=_ts(base, i * 2), event_type="network", action="connection",
            dst_port=1000 + i,
        )
        for i in range(3)
    ]
    assert detect_port_scan(events) == []


def test_blacklisted_ip_triggers_once_per_ip():
    events = [
        _event(src_ip="9.9.9.9", threat_intel={"category": "c2-server", "confidence": 95, "source": "test"}),
        _event(src_ip="9.9.9.9", threat_intel={"category": "c2-server", "confidence": 95, "source": "test"}),
    ]
    alerts = detect_blacklisted_ip(events)
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "critical"


def test_blacklisted_ip_ignores_clean_events():
    events = [_event(src_ip="9.9.9.9", threat_intel=None)]
    assert detect_blacklisted_ip(events) == []


def test_impossible_travel_triggers_across_distant_countries():
    base = "2026-01-01T00:00:00Z"
    events = [
        _event(timestamp=base, user="bob", country="IN", src_ip="1.1.1.1"),
        _event(timestamp=_ts(base, 240), user="bob", country="US", src_ip="2.2.2.2"),
    ]
    alerts = detect_impossible_travel(events)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "impossible_travel"


def test_impossible_travel_allows_realistic_gaps():
    base = "2026-01-01T00:00:00Z"
    events = [
        _event(timestamp=base, user="bob", country="IN", src_ip="1.1.1.1"),
        _event(timestamp=_ts(base, 3600 * 20), user="bob", country="US", src_ip="2.2.2.2"),
    ]
    assert detect_impossible_travel(events) == []
