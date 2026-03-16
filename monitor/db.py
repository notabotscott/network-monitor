"""
Database backend for network-monitor.

Two backends are supported, selected by the DATABASE_URL scheme:
  sqlite:///path/to/file.db      — local development, no extra dependencies
  postgresql://user:pass@host/db — production (requires psycopg2-binary)

Every query is automatically scoped to the client_id supplied at construction
time, so multiple clients can share a single database without data leakage.

Schema notes:
  - client_id is stored on scans, host_snapshots, dns_snapshots, change_events.
    port_snapshots and http_snapshots are always accessed through host_snapshot_id
    which is already client-scoped, so they don't need it.
  - Arrays (hostnames, a_records, etc.) are stored as JSON TEXT for SQLite compat.
  - Timestamps are stored as ISO-8601 TEXT for SQLite compat.
  - Booleans are stored as INTEGER (0/1) for SQLite compat.
  - port_snapshots and http_snapshots are loaded in bulk (one query per scan)
    to avoid N+1 problems on large subnets.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .dns import DnsRecord
from .differ import ChangeEvent
from .scanner import HostState, PortInfo

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SQLITE_DDL = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id    TEXT    NOT NULL,
    started_at   TEXT    NOT NULL,
    completed_at TEXT,
    targets      TEXT    NOT NULL DEFAULT '[]',
    status       TEXT    NOT NULL DEFAULT 'running'
);
CREATE INDEX IF NOT EXISTS idx_scans_client ON scans(client_id);

CREATE TABLE IF NOT EXISTS host_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id   TEXT    NOT NULL,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    scanned_at  TEXT    NOT NULL,
    ip          TEXT    NOT NULL,
    hostnames   TEXT    NOT NULL DEFAULT '[]',
    is_up       INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_hs_client_ip_scan ON host_snapshots(client_id, ip, scan_id);

CREATE TABLE IF NOT EXISTS port_snapshots (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    host_snapshot_id  INTEGER NOT NULL REFERENCES host_snapshots(id),
    port              INTEGER NOT NULL,
    protocol          TEXT    NOT NULL DEFAULT 'tcp',
    state             TEXT    NOT NULL,
    service           TEXT    NOT NULL DEFAULT '',
    product           TEXT    NOT NULL DEFAULT '',
    version           TEXT    NOT NULL DEFAULT '',
    extrainfo         TEXT    NOT NULL DEFAULT '',
    cpe               TEXT    NOT NULL DEFAULT '',
    banner            TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ps_host ON port_snapshots(host_snapshot_id);

CREATE TABLE IF NOT EXISTS http_snapshots (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    host_snapshot_id  INTEGER NOT NULL REFERENCES host_snapshots(id),
    label             TEXT    NOT NULL,
    headers           TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_http_host ON http_snapshots(host_snapshot_id);

CREATE TABLE IF NOT EXISTS dns_snapshots (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id         TEXT    NOT NULL,
    scan_id           INTEGER NOT NULL REFERENCES scans(id),
    scanned_at        TEXT    NOT NULL,
    fqdn              TEXT    NOT NULL,
    a_records         TEXT    NOT NULL DEFAULT '[]',
    aaaa_records      TEXT    NOT NULL DEFAULT '[]',
    cname             TEXT,
    ttl               INTEGER,
    resolution_failed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_dns_client_fqdn_scan ON dns_snapshots(client_id, fqdn, scan_id);

CREATE TABLE IF NOT EXISTS change_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id      TEXT    NOT NULL,
    detected_at    TEXT    NOT NULL,
    scan_id        INTEGER REFERENCES scans(id),
    target         TEXT    NOT NULL,
    host_ip        TEXT    NOT NULL,
    change_type    TEXT    NOT NULL,
    severity       TEXT    NOT NULL,
    port           TEXT,
    previous_value TEXT,
    current_value  TEXT,
    extra          TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_ce_client          ON change_events(client_id);
CREATE INDEX IF NOT EXISTS idx_ce_client_host     ON change_events(client_id, host_ip);
CREATE INDEX IF NOT EXISTS idx_ce_client_type     ON change_events(client_id, change_type);
CREATE INDEX IF NOT EXISTS idx_ce_client_severity ON change_events(client_id, severity);
"""

_POSTGRES_DDL = """
CREATE TABLE IF NOT EXISTS scans (
    id           BIGSERIAL PRIMARY KEY,
    client_id    TEXT        NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    targets      TEXT        NOT NULL DEFAULT '[]',
    status       TEXT        NOT NULL DEFAULT 'running'
);
CREATE INDEX IF NOT EXISTS idx_scans_client ON scans(client_id);

CREATE TABLE IF NOT EXISTS host_snapshots (
    id          BIGSERIAL PRIMARY KEY,
    client_id   TEXT    NOT NULL,
    scan_id     BIGINT  NOT NULL REFERENCES scans(id),
    scanned_at  TIMESTAMPTZ NOT NULL,
    ip          TEXT    NOT NULL,
    hostnames   TEXT    NOT NULL DEFAULT '[]',
    is_up       BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_hs_client_ip_scan ON host_snapshots(client_id, ip, scan_id);

CREATE TABLE IF NOT EXISTS port_snapshots (
    id               BIGSERIAL PRIMARY KEY,
    host_snapshot_id BIGINT  NOT NULL REFERENCES host_snapshots(id),
    port             INTEGER NOT NULL,
    protocol         TEXT    NOT NULL DEFAULT 'tcp',
    state            TEXT    NOT NULL,
    service          TEXT    NOT NULL DEFAULT '',
    product          TEXT    NOT NULL DEFAULT '',
    version          TEXT    NOT NULL DEFAULT '',
    extrainfo        TEXT    NOT NULL DEFAULT '',
    cpe              TEXT    NOT NULL DEFAULT '',
    banner           TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ps_host ON port_snapshots(host_snapshot_id);

CREATE TABLE IF NOT EXISTS http_snapshots (
    id               BIGSERIAL PRIMARY KEY,
    host_snapshot_id BIGINT NOT NULL REFERENCES host_snapshots(id),
    label            TEXT   NOT NULL,
    headers          TEXT   NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_http_host ON http_snapshots(host_snapshot_id);

CREATE TABLE IF NOT EXISTS dns_snapshots (
    id                BIGSERIAL PRIMARY KEY,
    client_id         TEXT        NOT NULL,
    scan_id           BIGINT      NOT NULL REFERENCES scans(id),
    scanned_at        TIMESTAMPTZ NOT NULL,
    fqdn              TEXT        NOT NULL,
    a_records         TEXT        NOT NULL DEFAULT '[]',
    aaaa_records      TEXT        NOT NULL DEFAULT '[]',
    cname             TEXT,
    ttl               INTEGER,
    resolution_failed BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_dns_client_fqdn_scan ON dns_snapshots(client_id, fqdn, scan_id);

CREATE TABLE IF NOT EXISTS change_events (
    id             BIGSERIAL PRIMARY KEY,
    client_id      TEXT        NOT NULL,
    detected_at    TIMESTAMPTZ NOT NULL,
    scan_id        BIGINT REFERENCES scans(id),
    target         TEXT NOT NULL,
    host_ip        TEXT NOT NULL,
    change_type    TEXT NOT NULL,
    severity       TEXT NOT NULL,
    port           TEXT,
    previous_value TEXT,
    current_value  TEXT,
    extra          TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_ce_client          ON change_events(client_id);
CREATE INDEX IF NOT EXISTS idx_ce_client_host     ON change_events(client_id, host_ip);
CREATE INDEX IF NOT EXISTS idx_ce_client_type     ON change_events(client_id, change_type);
CREATE INDEX IF NOT EXISTS idx_ce_client_severity ON change_events(client_id, severity);
"""

# ---------------------------------------------------------------------------
# Thin connection wrapper (normalises ? vs %s, last-insert-id)
# ---------------------------------------------------------------------------

class _Conn:
    """Wraps a raw DB-API 2 connection with a uniform interface."""

    def __init__(self, raw_conn: Any, is_postgres: bool) -> None:
        self._conn = raw_conn
        self._pg = is_postgres
        self._ph = "%s" if is_postgres else "?"

    def _q(self, sql: str) -> str:
        return sql.replace("?", self._ph) if self._pg else sql

    def execute(self, sql: str, params: tuple = ()) -> Any:
        cur = self._conn.cursor()
        cur.execute(self._q(sql), params)
        return cur

    def executemany(self, sql: str, params_seq) -> None:
        cur = self._conn.cursor()
        cur.executemany(self._q(sql), params_seq)

    def insert(self, sql: str, params: tuple = ()) -> int:
        """Execute an INSERT and return the new row's id."""
        if self._pg:
            cur = self._conn.cursor()
            cur.execute(self._q(sql) + " RETURNING id", params)
            return cur.fetchone()[0]
        else:
            cur = self._conn.cursor()
            cur.execute(self._q(sql), params)
            return cur.lastrowid

    def fetchone(self, sql: str, params: tuple = ()) -> Optional[Tuple]:
        return self.execute(sql, params).fetchone()

    def fetchall(self, sql: str, params: tuple = ()) -> List[Tuple]:
        return self.execute(sql, params).fetchall()

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def run_script(self, ddl: str) -> None:
        if self._pg:
            self._conn.cursor().execute(ddl)
        else:
            self._conn.executescript(ddl)
        self._conn.commit()


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    """
    High-level interface used by the scanner (write) and differ (read/write).
    All operations are automatically scoped to client_id.

    SQLite  : sqlite:///absolute/path/to/file.db
    Postgres: postgresql://user:password@host:5432/dbname
              postgresql://user:password@/cloudsql/PROJECT:REGION:INSTANCE/dbname
    """

    def __init__(self, url: str, client_id: str) -> None:
        if not client_id:
            raise ValueError("client_id must be a non-empty string")
        self._cid = client_id
        self._conn = _connect(url)
        self._init_schema(url)
        self._migrate()
        logger.info("Database connected", extra={"url": _redact(url), "client_id": client_id})

    def _init_schema(self, url: str) -> None:
        ddl = _POSTGRES_DDL if url.startswith(("postgres", "postgresql")) else _SQLITE_DDL
        self._conn.run_script(ddl)

    def _migrate(self) -> None:
        """
        Add client_id to tables that predate multi-client support.
        Safe to run repeatedly — ignores 'column already exists' errors.
        """
        for table in ("scans", "host_snapshots", "dns_snapshots", "change_events"):
            try:
                self._conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN client_id TEXT NOT NULL DEFAULT 'default'"
                )
                self._conn.commit()
                logger.info("Migration: added client_id to %s", table)
            except Exception:
                pass  # column already exists

    # ------------------------------------------------------------------
    # Write — scanner
    # ------------------------------------------------------------------

    def begin_scan(self, targets: List[str]) -> int:
        scan_id = self._conn.insert(
            "INSERT INTO scans (client_id, started_at, targets, status) VALUES (?, ?, ?, 'running')",
            (self._cid, _now_iso(), json.dumps(targets)),
        )
        self._conn.commit()
        logger.debug("Scan started", extra={"scan_id": scan_id, "client_id": self._cid})
        return scan_id

    def complete_scan(self, scan_id: int) -> None:
        self._conn.execute(
            "UPDATE scans SET status='completed', completed_at=? WHERE id=? AND client_id=?",
            (_now_iso(), scan_id, self._cid),
        )
        self._conn.commit()

    def fail_scan(self, scan_id: int) -> None:
        self._conn.execute(
            "UPDATE scans SET status='failed', completed_at=? WHERE id=? AND client_id=?",
            (_now_iso(), scan_id, self._cid),
        )
        self._conn.commit()

    def write_host_snapshot(self, scan_id: int, host: HostState) -> None:
        host_id = self._conn.insert(
            "INSERT INTO host_snapshots (client_id, scan_id, scanned_at, ip, hostnames, is_up) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (self._cid, scan_id, _now_iso(), host.ip,
             json.dumps(host.hostnames), int(host.is_up)),
        )
        self._conn.executemany(
            "INSERT INTO port_snapshots "
            "(host_snapshot_id, port, protocol, state, service, product, version, extrainfo, cpe, banner) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (host_id, int(key.split("/")[0]), key.split("/")[1],
                 p.state, p.service, p.product, p.version, p.extrainfo, p.cpe, p.banner)
                for key, p in host.ports.items()
            ],
        )
        self._conn.executemany(
            "INSERT INTO http_snapshots (host_snapshot_id, label, headers) VALUES (?, ?, ?)",
            [(host_id, label, json.dumps(hdrs)) for label, hdrs in host.http_headers.items()],
        )
        self._conn.commit()

    def write_dns_snapshot(self, scan_id: int, record: DnsRecord) -> None:
        self._conn.insert(
            "INSERT INTO dns_snapshots "
            "(client_id, scan_id, scanned_at, fqdn, a_records, aaaa_records, cname, ttl, resolution_failed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (self._cid, scan_id, _now_iso(), record.fqdn,
             json.dumps(record.a_records), json.dumps(record.aaaa_records),
             record.cname, record.ttl, int(record.resolution_failed)),
        )
        self._conn.commit()

    def write_change_events(self, scan_id: int, events: List[ChangeEvent]) -> None:
        if not events:
            return
        self._conn.executemany(
            "INSERT INTO change_events "
            "(client_id, detected_at, scan_id, target, host_ip, change_type, severity, "
            " port, previous_value, current_value, extra) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (self._cid, _now_iso(), scan_id, e.target, e.host_ip,
                 e.change_type, e.severity, e.port,
                 e.previous, e.current, json.dumps(e.extra))
                for e in events
            ],
        )
        self._conn.commit()
        logger.debug("Wrote %d change events", len(events), extra={"client_id": self._cid})

    # ------------------------------------------------------------------
    # Read — differ
    # ------------------------------------------------------------------

    def get_latest_completed_scan_id(self) -> Optional[int]:
        row = self._conn.fetchone(
            "SELECT id FROM scans WHERE client_id=? AND status='completed' ORDER BY id DESC LIMIT 1",
            (self._cid,),
        )
        return row[0] if row else None

    def get_scan_targets(self, scan_id: int) -> List[str]:
        row = self._conn.fetchone(
            "SELECT targets FROM scans WHERE id=? AND client_id=?",
            (scan_id, self._cid),
        )
        return json.loads(row[0]) if row else []

    def get_hosts_in_scan(self, scan_id: int) -> Dict[str, HostState]:
        """Load all HostState objects for a scan in three bulk queries."""
        host_rows = self._conn.fetchall(
            "SELECT id, ip, hostnames, is_up, scanned_at FROM host_snapshots "
            "WHERE client_id=? AND scan_id=?",
            (self._cid, scan_id),
        )
        if not host_rows:
            return {}

        host_ids = [r[0] for r in host_rows]
        placeholders = ",".join("?" * len(host_ids))

        port_rows = self._conn.fetchall(
            f"SELECT host_snapshot_id, port, protocol, state, service, product, "
            f"version, extrainfo, cpe, banner FROM port_snapshots "
            f"WHERE host_snapshot_id IN ({placeholders})",
            tuple(host_ids),
        )
        http_rows = self._conn.fetchall(
            f"SELECT host_snapshot_id, label, headers FROM http_snapshots "
            f"WHERE host_snapshot_id IN ({placeholders})",
            tuple(host_ids),
        )

        ports_by_host: Dict[int, Dict[str, PortInfo]] = {hid: {} for hid in host_ids}
        for row in port_rows:
            hid, port, proto, state, svc, prod, ver, extra, cpe, banner = row
            ports_by_host[hid][f"{port}/{proto}"] = PortInfo(
                state=state, service=svc, product=prod, version=ver,
                extrainfo=extra, cpe=cpe, banner=banner,
            )

        http_by_host: Dict[int, Dict[str, Dict]] = {hid: {} for hid in host_ids}
        for row in http_rows:
            hid, label, headers_json = row
            http_by_host[hid][label] = json.loads(headers_json)

        result: Dict[str, HostState] = {}
        for hid, ip, hostnames_json, is_up, scanned_at in host_rows:
            result[ip] = HostState(
                ip=ip,
                hostnames=json.loads(hostnames_json),
                timestamp=_parse_ts(scanned_at),
                ports=ports_by_host[hid],
                http_headers=http_by_host[hid],
                is_up=bool(is_up),
            )
        return result

    def get_previous_host_state(self, ip: str, before_scan_id: int) -> Optional[HostState]:
        """Most recent host snapshot for this client with scan_id < before_scan_id."""
        row = self._conn.fetchone(
            "SELECT id, ip, hostnames, is_up, scanned_at FROM host_snapshots "
            "WHERE client_id=? AND ip=? AND scan_id<? ORDER BY scan_id DESC LIMIT 1",
            (self._cid, ip, before_scan_id),
        )
        if not row:
            return None
        hid, ip, hostnames_json, is_up, scanned_at = row

        port_rows = self._conn.fetchall(
            "SELECT port, protocol, state, service, product, version, extrainfo, cpe, banner "
            "FROM port_snapshots WHERE host_snapshot_id=?",
            (hid,),
        )
        http_rows = self._conn.fetchall(
            "SELECT label, headers FROM http_snapshots WHERE host_snapshot_id=?",
            (hid,),
        )
        ports = {
            f"{port}/{proto}": PortInfo(
                state=state, service=svc, product=prod, version=ver,
                extrainfo=extra, cpe=cpe, banner=banner,
            )
            for port, proto, state, svc, prod, ver, extra, cpe, banner in port_rows
        }
        return HostState(
            ip=ip,
            hostnames=json.loads(hostnames_json),
            timestamp=_parse_ts(scanned_at),
            ports=ports,
            http_headers={label: json.loads(hdrs) for label, hdrs in http_rows},
            is_up=bool(is_up),
        )

    def get_dns_in_scan(self, scan_id: int) -> Dict[str, DnsRecord]:
        rows = self._conn.fetchall(
            "SELECT fqdn, a_records, aaaa_records, cname, ttl, resolution_failed, scanned_at "
            "FROM dns_snapshots WHERE client_id=? AND scan_id=?",
            (self._cid, scan_id),
        )
        return {
            fqdn: DnsRecord(
                fqdn=fqdn, timestamp=_parse_ts(ts),
                a_records=json.loads(a_json), aaaa_records=json.loads(aaaa_json),
                cname=cname, ttl=ttl, resolution_failed=bool(failed),
            )
            for fqdn, a_json, aaaa_json, cname, ttl, failed, ts in rows
        }

    def get_previous_dns_record(self, fqdn: str, before_scan_id: int) -> Optional[DnsRecord]:
        row = self._conn.fetchone(
            "SELECT fqdn, a_records, aaaa_records, cname, ttl, resolution_failed, scanned_at "
            "FROM dns_snapshots WHERE client_id=? AND fqdn=? AND scan_id<? "
            "ORDER BY scan_id DESC LIMIT 1",
            (self._cid, fqdn, before_scan_id),
        )
        if not row:
            return None
        fqdn, a_json, aaaa_json, cname, ttl, failed, ts = row
        return DnsRecord(
            fqdn=fqdn, timestamp=_parse_ts(ts),
            a_records=json.loads(a_json), aaaa_records=json.loads(aaaa_json),
            cname=cname, ttl=ttl, resolution_failed=bool(failed),
        )

    def close(self) -> None:
        self._conn.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _connect(url: str) -> _Conn:
    if url.startswith(("postgresql://", "postgres://")):
        try:
            import psycopg2
        except ImportError as exc:
            raise ImportError(
                "psycopg2-binary is required for PostgreSQL. "
                "Add it to requirements.txt and rebuild."
            ) from exc
        raw = psycopg2.connect(url)
        raw.autocommit = False
        return _Conn(raw, is_postgres=True)

    path = url.removeprefix("sqlite:///")
    raw = sqlite3.connect(path, check_same_thread=False)
    raw.execute("PRAGMA journal_mode=WAL")
    raw.execute("PRAGMA foreign_keys=ON")
    return _Conn(raw, is_postgres=False)


def _parse_ts(ts_str: str) -> float:
    try:
        return datetime.fromisoformat(ts_str).timestamp()
    except (ValueError, TypeError):
        return time.time()


def _redact(url: str) -> str:
    import re
    return re.sub(r"://([^:@/]+):([^@/]+)@", r"://\1:***@", url)
