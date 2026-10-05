"""SQLite storage for alerts. Kept intentionally simple (stdlib sqlite3,
no ORM) so the project has no database server dependency.
"""

import json
import sqlite3
from contextlib import contextmanager

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    src_ip TEXT,
    user TEXT,
    event_timestamp TEXT NOT NULL,
    evidence TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
"""


@contextmanager
def get_conn(db_path=config.DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path=config.DB_PATH):
    with get_conn(db_path) as conn:
        conn.executescript(SCHEMA)


def insert_alerts(alerts, db_path=config.DB_PATH):
    with get_conn(db_path) as conn:
        for a in alerts:
            conn.execute(
                """INSERT INTO alerts
                   (rule, severity, title, description, src_ip, user, event_timestamp, evidence)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    a["rule"], a["severity"], a["title"], a["description"],
                    a.get("src_ip"), a.get("user"), a["timestamp"],
                    json.dumps(a.get("evidence", {})),
                ),
            )


def get_alerts(db_path=config.DB_PATH, status=None, severity=None, limit=200):
    query = "SELECT * FROM alerts"
    clauses, params = [], []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with get_conn(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def update_alert_status(alert_id, status, db_path=config.DB_PATH):
    with get_conn(db_path) as conn:
        conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))


def get_stats(db_path=config.DB_PATH):
    with get_conn(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
        by_severity = {
            row["severity"]: row["c"]
            for row in conn.execute("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity")
        }
        by_rule = {
            row["rule"]: row["c"]
            for row in conn.execute("SELECT rule, COUNT(*) c FROM alerts GROUP BY rule")
        }
        top_ips = [
            dict(row) for row in conn.execute(
                "SELECT src_ip, COUNT(*) c FROM alerts WHERE src_ip IS NOT NULL "
                "GROUP BY src_ip ORDER BY c DESC LIMIT 10"
            )
        ]
        open_count = conn.execute(
            "SELECT COUNT(*) c FROM alerts WHERE status = 'open'"
        ).fetchone()["c"]
        return {
            "total": total,
            "open": open_count,
            "by_severity": by_severity,
            "by_rule": by_rule,
            "top_ips": top_ips,
        }


def clear_alerts(db_path=config.DB_PATH):
    with get_conn(db_path) as conn:
        conn.execute("DELETE FROM alerts")
