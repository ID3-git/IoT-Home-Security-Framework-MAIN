"""
SQLite persistence layer for scan results.

Database file location: database/iot_vuln.db (relative to the project root,
resolved at import time from this file's location).  Override with the
DB_PATH environment variable.

Schema (four normalised tables):
  scans    — one row per scan run
  devices  — one row per discovered host per scan
  services — one row per detected port/service per device
  cves     — one row per CVE associated with a device

All writes go through insert_scan(); all reads through get_scans() and
get_scan_devices().  compare_scans() performs a two-scan diff for the
historical comparison view in the GUI.
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

# Resolve the default database path relative to this file so the module works
# regardless of the current working directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_DB = os.path.join(_HERE, "iot_vuln.db")
DB_PATH: str = os.environ.get("DB_PATH", _DEFAULT_DB)


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
    scan_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT    NOT NULL,   -- ISO-8601 UTC timestamp
    subnet       TEXT    NOT NULL,   -- CIDR string or 'auto'
    device_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS devices (
    device_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    ip         TEXT    NOT NULL,
    mac        TEXT    NOT NULL DEFAULT '',
    vendor     TEXT    NOT NULL DEFAULT '',
    hostname   TEXT    NOT NULL DEFAULT '',
    os_guess   TEXT    NOT NULL DEFAULT '',
    risk_level TEXT    NOT NULL DEFAULT 'Info',
    risk_score REAL    NOT NULL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS services (
    service_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT    NOT NULL DEFAULT 'tcp',
    state       TEXT    NOT NULL DEFAULT '',
    name        TEXT    NOT NULL DEFAULT '',
    product     TEXT    NOT NULL DEFAULT '',
    version     TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS cves (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    cve_id      TEXT    NOT NULL,
    cvss_score  REAL    NOT NULL DEFAULT 0.0,
    severity    TEXT    NOT NULL DEFAULT '',
    description TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_devices_scan   ON devices(scan_id);
CREATE INDEX IF NOT EXISTS idx_services_dev   ON services(device_id);
CREATE INDEX IF NOT EXISTS idx_cves_dev       ON cves(device_id);
CREATE INDEX IF NOT EXISTS idx_devices_ip     ON devices(ip);
"""


# ── Connection helper ─────────────────────────────────────────────────────────

@contextmanager
def _connect():
    """Yield a thread-local SQLite connection with WAL mode and FK enforcement."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Initialisation ────────────────────────────────────────────────────────────

def init_db(path: Optional[str] = None) -> None:
    """
    Create the database file and apply the schema if they do not already exist.

    Safe to call on every application start — all CREATE statements use
    IF NOT EXISTS, so repeated calls are idempotent.

    Args:
        path: Override the database file path (used in tests).
    """
    global DB_PATH
    if path:
        DB_PATH = path
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _connect() as conn:
        conn.executescript(_SCHEMA)


# ── Write ─────────────────────────────────────────────────────────────────────

def insert_scan(
    results: list[dict],
    subnet: str = "auto",
) -> int:
    """
    Persist a complete scan result set and return the new scan_id.

    Args:
        results: List of device dicts as produced by the GUI pipeline —
                 each dict contains ip, mac, vendor, hostname, os_guess,
                 risk_level, risk_score, services (list), and cves (list).
        subnet:  The subnet string passed to discover(), or 'auto'.

    Returns:
        The integer scan_id of the newly inserted scan row.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans (started_at, subnet, device_count) VALUES (?, ?, ?)",
            (timestamp, subnet or "auto", len(results)),
        )
        scan_id: int = cur.lastrowid  # type: ignore[assignment]

        for device in results:
            dcur = conn.execute(
                """INSERT INTO devices
                   (scan_id, ip, mac, vendor, hostname, os_guess, risk_level, risk_score)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    device.get("ip", ""),
                    device.get("mac", ""),
                    device.get("vendor", ""),
                    device.get("hostname", ""),
                    device.get("os_guess", ""),
                    device.get("risk_level", "Info"),
                    float(device.get("risk_score", 0.0)),
                ),
            )
            device_id: int = dcur.lastrowid  # type: ignore[assignment]

            for svc in device.get("services", []):
                conn.execute(
                    """INSERT INTO services
                       (device_id, port, protocol, state, name, product, version)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        device_id,
                        int(svc.get("port", 0)),
                        svc.get("protocol", "tcp"),
                        svc.get("state", ""),
                        svc.get("name", ""),
                        svc.get("product", ""),
                        svc.get("version", ""),
                    ),
                )

            for cve in device.get("cves", []):
                conn.execute(
                    """INSERT INTO cves
                       (device_id, cve_id, cvss_score, severity, description)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        device_id,
                        cve.get("cve_id", ""),
                        float(cve.get("cvss_score", 0.0)),
                        cve.get("severity", ""),
                        cve.get("description", "")[:500],
                    ),
                )

    return scan_id


# ── Read ──────────────────────────────────────────────────────────────────────

def get_scans() -> list[dict]:
    """
    Return all scan runs ordered newest first.

    Each dict contains: scan_id, started_at, subnet, device_count.
    """
    with _connect() as conn:
        rows = conn.execute(
            "SELECT scan_id, started_at, subnet, device_count "
            "FROM scans ORDER BY scan_id DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan_devices(scan_id: int) -> list[dict]:
    """
    Return all devices for a given scan_id, each with nested services and CVEs.

    Returns the same dict structure as the GUI pipeline so results can be
    passed directly to risk_engine, advisor, or the GUI result view.
    """
    with _connect() as conn:
        device_rows = conn.execute(
            "SELECT * FROM devices WHERE scan_id = ? ORDER BY ip",
            (scan_id,),
        ).fetchall()

        results = []
        for drow in device_rows:
            device_id = drow["device_id"]

            svc_rows = conn.execute(
                "SELECT port, protocol, state, name, product, version "
                "FROM services WHERE device_id = ?",
                (device_id,),
            ).fetchall()

            cve_rows = conn.execute(
                "SELECT cve_id, cvss_score, severity, description "
                "FROM cves WHERE device_id = ?",
                (device_id,),
            ).fetchall()

            results.append({
                "ip":         drow["ip"],
                "mac":        drow["mac"],
                "vendor":     drow["vendor"],
                "hostname":   drow["hostname"],
                "os_guess":   drow["os_guess"],
                "risk_level": drow["risk_level"],
                "risk_score": drow["risk_score"],
                "services":   [dict(r) for r in svc_rows],
                "cves":       [dict(r) for r in cve_rows],
                "risk_reasons": [],
            })
    return results


# ── Historical comparison ─────────────────────────────────────────────────────

def compare_scans(scan_id_a: int, scan_id_b: int) -> dict:
    """
    Diff two scans and return a structured change report.

    Args:
        scan_id_a: The earlier (baseline) scan.
        scan_id_b: The later (current) scan.

    Returns a dict with four keys:
        new_devices     — IPs present in B but not A
        removed_devices — IPs present in A but not B
        risk_increased  — IPs whose risk_level worsened between A and B
        risk_decreased  — IPs whose risk_level improved between A and B

    Risk levels are ordered: Info < Low < Medium < High < Critical.
    """
    _ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    a_devices = {d["ip"]: d for d in get_scan_devices(scan_id_a)}
    b_devices = {d["ip"]: d for d in get_scan_devices(scan_id_b)}

    a_ips = set(a_devices)
    b_ips = set(b_devices)

    new_devices     = [b_devices[ip] for ip in (b_ips - a_ips)]
    removed_devices = [a_devices[ip] for ip in (a_ips - b_ips)]

    risk_increased = []
    risk_decreased = []
    for ip in a_ips & b_ips:
        lvl_a = _ORDER.get(a_devices[ip]["risk_level"], 0)
        lvl_b = _ORDER.get(b_devices[ip]["risk_level"], 0)
        if lvl_b > lvl_a:
            risk_increased.append(b_devices[ip])
        elif lvl_b < lvl_a:
            risk_decreased.append(b_devices[ip])

    return {
        "new_devices":     new_devices,
        "removed_devices": removed_devices,
        "risk_increased":  risk_increased,
        "risk_decreased":  risk_decreased,
    }
