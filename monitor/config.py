from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List

import yaml


@dataclass
class Config:
    # Targets: IPs, FQDNs, or CIDRs
    targets: List[str]

    # nmap options
    nmap_arguments: str = "-sV --open -T4"
    nmap_ports: str = "top-1000"
    nmap_sudo: bool = False  # True enables SYN scan (-sS) but needs CAP_NET_RAW

    # HTTP probing
    http_timeout: int = 10
    http_follow_redirects: bool = True
    http_max_redirects: int = 3
    http_user_agent: str = "NetworkMonitor/1.0"
    http_headers_of_interest: List[str] = field(default_factory=lambda: [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Generator",
        "X-Drupal-Cache",
        "Via",
        "X-Varnish",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
    ])

    # Banner grabbing (non-HTTP open TCP ports)
    banner_grab: bool = True
    banner_grab_timeout: float = 4.0   # seconds per port; keep short — client-speaks-first
    banner_grab_max_bytes: int = 512   # bytes to read from each connection

    # State backend: "local" or "gcs"
    state_backend: str = "local"
    state_local_dir: str = "/data/state"
    state_gcs_bucket: str = ""
    state_gcs_prefix: str = "network-monitor/state"

    # Logging
    log_level: str = "INFO"
    log_changes_only: bool = False  # suppress no-change INFO scans

    # Alerting filter
    alert_min_severity: str = "info"  # info | warning | critical

    # Client identity — all data is scoped to this value.
    # Use a short, stable slug: "acme", "client-42", etc.
    client_id: str = "default"

    # Database
    # sqlite:///absolute/path/to/file.db  — local dev (no extra deps)
    # postgresql://user:pass@host/dbname  — production / Cloud SQL
    database_url: str = "sqlite:///data/monitor.db"

    # Monitor mode (controls what this process does each cycle):
    #   scan  — run nmap/DNS/banner, write snapshots to DB only
    #   diff  — read latest two snapshots from DB, detect changes, write change_events
    #   all   — scan then diff in the same process (simplest deployment)
    monitor_mode: str = "all"

    # Run mode
    run_mode: str = "job"  # "job" (single-shot) or "service" (internal loop)
    scan_interval_seconds: int = 3600  # only used in "service" mode

    @classmethod
    def from_env(cls) -> "Config":
        """Build a single Config from environment variables, with optional YAML base file.

        If CONFIG_FILE points to a YAML with a ``clients:`` section, raises
        ValueError — use :func:`load_all_configs` instead.
        """
        raw: dict = {}

        yaml_path = os.environ.get("CONFIG_FILE")
        if yaml_path:
            with open(yaml_path) as f:
                raw = yaml.safe_load(f) or {}
            if "clients" in raw:
                raise ValueError(
                    "CONFIG_FILE contains a 'clients' section — "
                    "use load_all_configs() instead of Config.from_env()."
                )

        raw = _apply_env_overrides(raw)

        if "targets" not in raw or not raw["targets"]:
            raise ValueError(
                "No scan targets configured. "
                "Set MONITOR_TARGETS or provide targets in CONFIG_FILE."
            )

        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in raw.items() if k in known})

    @classmethod
    def from_yaml_clients(cls, yaml_path: str) -> "List[Config]":
        """Parse a multi-client YAML config file and return one Config per client.

        YAML structure::

            # Global defaults — inherited by every client
            database_url: postgresql://user:pass@host/dbname
            nmap_ports: top-1000
            log_level: INFO

            clients:
              acme:
                targets:
                  - 203.0.113.0/24
                  - api.acme.com
              globex:
                targets:
                  - 198.51.100.0/28
                nmap_ports: top-500   # per-client override

        Environment variables (DATABASE_URL, MONITOR_LOG_LEVEL, …) override the
        global defaults but do NOT override per-client values — per-client YAML
        always wins over env vars for client-specific settings.
        """
        with open(yaml_path) as f:
            raw = yaml.safe_load(f) or {}

        clients_section: Dict[str, dict] = raw.pop("clients", None)
        if not clients_section:
            raise ValueError(f"No 'clients' section found in {yaml_path!r}")

        # Apply env overrides to the global section only
        global_defaults = _apply_env_overrides(dict(raw))

        known = set(cls.__dataclass_fields__)
        configs: List[Config] = []
        for client_id, client_overrides in clients_section.items():
            merged = {**global_defaults, **(client_overrides or {})}
            merged["client_id"] = client_id  # YAML key is always authoritative
            if "targets" not in merged or not merged["targets"]:
                raise ValueError(
                    f"Client {client_id!r} has no targets configured in {yaml_path!r}"
                )
            configs.append(cls(**{k: v for k, v in merged.items() if k in known}))

        return configs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _apply_env_overrides(raw: dict) -> dict:
    """Return a copy of *raw* with any relevant environment variables applied."""
    raw = dict(raw)

    if targets_env := os.environ.get("MONITOR_TARGETS"):
        raw["targets"] = [t.strip() for t in targets_env.split(",") if t.strip()]

    str_overrides = {
        "CLIENT_ID":                   "client_id",
        "DATABASE_URL":                "database_url",
        "MONITOR_MODE":                "monitor_mode",
        "MONITOR_NMAP_ARGUMENTS":      "nmap_arguments",
        "MONITOR_NMAP_PORTS":          "nmap_ports",
        "MONITOR_STATE_BACKEND":       "state_backend",
        "MONITOR_STATE_LOCAL_DIR":     "state_local_dir",
        "MONITOR_STATE_GCS_BUCKET":    "state_gcs_bucket",
        "MONITOR_STATE_GCS_PREFIX":    "state_gcs_prefix",
        "MONITOR_LOG_LEVEL":           "log_level",
        "MONITOR_ALERT_MIN_SEVERITY":  "alert_min_severity",
        "MONITOR_RUN_MODE":            "run_mode",
        "MONITOR_HTTP_USER_AGENT":     "http_user_agent",
    }
    for env_key, field_name in str_overrides.items():
        if val := os.environ.get(env_key):
            raw[field_name] = val

    int_overrides = {
        "MONITOR_HTTP_TIMEOUT":          "http_timeout",
        "MONITOR_HTTP_MAX_REDIRECTS":    "http_max_redirects",
        "MONITOR_SCAN_INTERVAL_SECONDS": "scan_interval_seconds",
        "MONITOR_BANNER_GRAB_MAX_BYTES": "banner_grab_max_bytes",
    }
    float_overrides = {
        "MONITOR_BANNER_GRAB_TIMEOUT": "banner_grab_timeout",
    }
    for env_key, field_name in float_overrides.items():
        if val := os.environ.get(env_key):
            raw[field_name] = float(val)
    for env_key, field_name in int_overrides.items():
        if val := os.environ.get(env_key):
            raw[field_name] = int(val)

    bool_overrides = {
        "MONITOR_NMAP_SUDO":             "nmap_sudo",
        "MONITOR_LOG_CHANGES_ONLY":      "log_changes_only",
        "MONITOR_HTTP_FOLLOW_REDIRECTS": "http_follow_redirects",
        "MONITOR_BANNER_GRAB":           "banner_grab",
    }
    for env_key, field_name in bool_overrides.items():
        if val := os.environ.get(env_key):
            raw[field_name] = val.lower() in ("1", "true", "yes")

    return raw


def load_all_configs() -> "List[Config]":
    """Return all configs to run this cycle.

    * If ``CONFIG_FILE`` points to a YAML with a ``clients:`` section →
      one :class:`Config` per client (multi-client mode).
    * Otherwise → a single :class:`Config` built from env vars / YAML base
      (backwards-compatible single-client mode).
    """
    yaml_path = os.environ.get("CONFIG_FILE")
    if yaml_path:
        with open(yaml_path) as f:
            probe = yaml.safe_load(f) or {}
        if "clients" in probe:
            return Config.from_yaml_clients(yaml_path)

    return [Config.from_env()]
