from __future__ import annotations

import json
import logging
import signal
import sys
import time
from typing import Dict, List, Optional, Set  # noqa: F401 (Set used in diff_phase)

from .config import Config, load_all_configs
from .db import Database
from .differ import ChangeEvent, Differ
from .dns import FqdnResolver, diff_dns, extract_fqdns
from .scanner import HostState, Scanner, expand_targets_to_ips


# ---------------------------------------------------------------------------
# Structured JSON logging — Cloud Logging parses these natively
# ---------------------------------------------------------------------------

class _CloudJsonFormatter(logging.Formatter):
    _SEVERITY = {
        "DEBUG": "DEBUG", "INFO": "INFO", "WARNING": "WARNING",
        "ERROR": "ERROR", "CRITICAL": "CRITICAL",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "severity": self._SEVERITY.get(record.levelname, "DEFAULT"),
            "message": record.getMessage(),
            "logger": record.name,
            "timestamp": record.created,
        }
        skip = set(logging.LogRecord.__init__.__code__.co_varnames) | {
            "message", "asctime", "exc_info", "exc_text", "stack_info",
            "msg", "args", "created", "levelname", "levelno", "name",
            "pathname", "filename", "module", "funcName", "lineno",
            "msecs", "relativeCreated", "thread", "threadName",
            "processName", "process", "taskName",
        }
        for key, val in record.__dict__.items():
            if key not in skip and not key.startswith("_"):
                payload[key] = val
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def _setup_logging(level: str) -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_CloudJsonFormatter())
    root.handlers = [handler]


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Phase 1 — Scan: collect data, write every snapshot to the database
# ---------------------------------------------------------------------------

def scan_phase(
    config: Config,
    scanner: Scanner,
    resolver: FqdnResolver,
    db: Database,
) -> int:
    """
    Run DNS resolution + nmap + banner grab + HTTP probe for all configured
    targets and persist every result to the database.

    Returns the scan_id of the newly created scan record.
    """
    scan_id = db.begin_scan(config.targets)
    try:
        # DNS snapshots
        fqdns = extract_fqdns(config.targets)
        if fqdns:
            dns_results = resolver.resolve_all(fqdns)
            for record in dns_results.values():
                db.write_dns_snapshot(scan_id, record)

        # Host / port / banner / HTTP snapshots
        hosts: Dict[str, HostState] = scanner.scan_targets(config.targets)
        for host in hosts.values():
            db.write_host_snapshot(scan_id, host)
        # Hosts that didn't respond are simply absent from this scan.
        # diff_phase detects HOST_DOWN by comparing known_ips_in_scope
        # against what's present in get_hosts_in_scan().

    except Exception:
        db.fail_scan(scan_id)
        raise

    db.complete_scan(scan_id)
    logger.info(
        "Scan phase complete",
        extra={"scan_id": scan_id, "targets": config.targets},
    )
    return scan_id


# ---------------------------------------------------------------------------
# Phase 2 — Diff: compare latest scan against previous, write change_events
# ---------------------------------------------------------------------------

def diff_phase(
    config: Config,
    db: Database,
    differ: Differ,
    scan_id: Optional[int] = None,
) -> List[ChangeEvent]:
    """
    Load the latest completed scan (or the given scan_id), compare every host
    and FQDN against the previous scan, persist ChangeEvents to change_events,
    and emit them as structured log records.

    Returns the list of ChangeEvents produced.
    """
    if scan_id is None:
        scan_id = db.get_latest_completed_scan_id()
        if scan_id is None:
            logger.info("Diff phase: no completed scans in database yet — skipping")
            return []

    targets = db.get_scan_targets(scan_id)
    now = time.time()
    all_events: List[ChangeEvent] = []

    # ── DNS diffs ────────────────────────────────────────────────────────
    dns_current = db.get_dns_in_scan(scan_id)
    for fqdn, current_record in dns_current.items():
        previous_record = db.get_previous_dns_record(fqdn, before_scan_id=scan_id)
        for d in diff_dns(fqdn, previous_record, current_record, now):
            all_events.append(_dict_to_event(d))

    # ── Host / port diffs ────────────────────────────────────────────────
    current_scan = db.get_hosts_in_scan(scan_id)
    in_scope: Set[str] = set(expand_targets_to_ips(targets))

    all_events.extend(
        differ.diff(
            target=",".join(targets),
            current_scan=current_scan,
            known_ips_in_scope=in_scope,
            store_get=lambda ip: db.get_previous_host_state(ip, before_scan_id=scan_id),
        )
    )

    # ── Persist and emit ─────────────────────────────────────────────────
    db.write_change_events(scan_id, all_events)

    for event in all_events:
        _emit_event(event)

    if not all_events and not config.log_changes_only:
        logger.info(
            "Diff phase complete — no changes detected",
            extra={"scan_id": scan_id, "hosts_checked": len(current_scan)},
        )
    else:
        logger.info(
            "Diff phase complete",
            extra={"scan_id": scan_id, "changes": len(all_events)},
        )

    return all_events


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dict_to_event(d: dict) -> ChangeEvent:
    return ChangeEvent(
        timestamp=d["timestamp"],
        target=d["target"],
        host_ip=d["host_ip"],
        change_type=d["change_type"],
        severity=d["severity"],
        port=d.get("port"),
        previous=d.get("previous"),
        current=d.get("current"),
        extra=d.get("extra", {}),
    )


def _emit_event(event: ChangeEvent) -> None:
    level_map = {"info": logging.INFO, "warning": logging.WARNING, "critical": logging.CRITICAL}
    level = level_map.get(event.severity, logging.INFO)
    parts = []
    if event.port:
        parts.append(f"port={event.port}")
    if event.previous is not None:
        parts.append(f"was={event.previous!r}")
    if event.current is not None:
        parts.append(f"now={event.current!r}")
    logger.log(
        level,
        "CHANGE [%s] %s%s",
        event.change_type,
        event.host_ip,
        " — " + " | ".join(parts) if parts else "",
        extra=event.to_dict(),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_shutdown = False


def _handle_sigterm(signum, frame) -> None:
    global _shutdown
    logger.info("SIGTERM received — finishing current cycle then exiting")
    _shutdown = True


def main() -> None:
    configs = load_all_configs()

    # Use the first config's log level and run_mode — these are global settings.
    _setup_logging(configs[0].log_level)

    logger.info(
        "Network monitor starting",
        extra={
            "clients": [c.client_id for c in configs],
            "run_mode": configs[0].run_mode,
            "monitor_mode": configs[0].monitor_mode,
        },
    )
    for cfg in configs:
        logger.info(
            "Client config loaded",
            extra={
                "client_id": cfg.client_id,
                "targets": cfg.targets,
                "nmap_ports": cfg.nmap_ports,
                "database_url": cfg.database_url.split("@")[-1],
            },
        )

    # Build per-client resources once; reuse across cycles.
    clients = [
        {
            "config": cfg,
            "db": Database(cfg.database_url, client_id=cfg.client_id),
            "scanner": Scanner(cfg),
            "resolver": FqdnResolver(),
            "differ": Differ(alert_min_severity=cfg.alert_min_severity),
        }
        for cfg in configs
    ]

    signal.signal(signal.SIGTERM, _handle_sigterm)

    def _run_all_clients() -> None:
        for client in clients:
            cfg = client["config"]
            db = client["db"]
            scanner = client["scanner"]
            resolver = client["resolver"]
            differ = client["differ"]
            mode = cfg.monitor_mode
            try:
                if mode == "scan":
                    scan_phase(cfg, scanner, resolver, db)
                elif mode == "diff":
                    diff_phase(cfg, db, differ)
                elif mode == "all":
                    scan_id = scan_phase(cfg, scanner, resolver, db)
                    diff_phase(cfg, db, differ, scan_id=scan_id)
                else:
                    raise ValueError(
                        f"Unknown MONITOR_MODE={mode!r}. Use: scan | diff | all"
                    )
            except Exception as exc:
                logger.error(
                    "Client cycle error: %s",
                    exc,
                    exc_info=True,
                    extra={"client_id": cfg.client_id},
                )
                # Emit a SCAN_FAILED change event so the log sink routes it
                # to Pub/Sub → Slack via the same pipeline as change events.
                logger.critical(
                    "SCAN_FAILED: %s",
                    exc,
                    extra={
                        "change_type": "SCAN_FAILED",
                        "severity": "critical",
                        "client_id": cfg.client_id,
                        "target": ",".join(cfg.targets),
                        "error": str(exc),
                    },
                )
                if configs[0].run_mode == "job":
                    for c in clients:
                        c["db"].close()
                    sys.exit(1)
                # In service mode, log and continue to next client

    run_mode = configs[0].run_mode
    if run_mode == "job":
        _run_all_clients()
        for client in clients:
            client["db"].close()
        sys.exit(0)

    else:  # service — internal loop
        while not _shutdown:
            _run_all_clients()

            if not _shutdown:
                interval = configs[0].scan_interval_seconds
                logger.info(
                    "Sleeping until next cycle",
                    extra={"interval_seconds": interval},
                )
                deadline = time.monotonic() + interval
                while time.monotonic() < deadline and not _shutdown:
                    time.sleep(1)

        for client in clients:
            client["db"].close()
        logger.info("Network monitor shut down cleanly")
        sys.exit(0)


if __name__ == "__main__":
    main()
