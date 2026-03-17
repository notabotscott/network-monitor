from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from .scanner import HostState, PortInfo

_SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}

_CHANGE_SEVERITY: Dict[str, str] = {
    "NEW_HOST":            "warning",
    "HOST_DOWN":           "critical",
    "PORT_OPENED":         "critical",
    "PORT_CLOSED":         "info",
    "SERVICE_CHANGED":     "warning",
    "VERSION_CHANGED":     "info",
    "BANNER_CHANGED":      "info",
    "HTTP_HEADER_CHANGED": "info",
}


@dataclass
class ChangeEvent:
    timestamp: float
    target: str           # original scan target string
    host_ip: str
    change_type: str
    severity: str
    client_id: str = ""
    port: Optional[str] = None      # e.g. "443/tcp" or "443/https"
    previous: Optional[str] = None  # human-readable previous value
    current: Optional[str] = None   # human-readable current value
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "host_ip": self.host_ip,
            "change_type": self.change_type,
            "severity": self.severity,
            "client_id": self.client_id,
            "port": self.port,
            "previous": self.previous,
            "current": self.current,
            "extra": self.extra,
        }


class Differ:
    def __init__(self, alert_min_severity: str = "info") -> None:
        self._min_severity = _SEVERITY_ORDER.get(alert_min_severity.lower(), 0)

    def diff(
        self,
        target: str,
        current_scan: Dict[str, HostState],
        known_ips_in_scope: Set[str],
        store_get: Callable[[str], Optional[HostState]],
    ) -> List[ChangeEvent]:
        """
        Compare current_scan against stored state and return ChangeEvents.

        known_ips_in_scope: every IP that was in the scan target range.
            IPs that were previously up but absent from current_scan are
            emitted as HOST_DOWN events.
        store_get: callable matching StateStore.get() signature.
        """
        events: List[ChangeEvent] = []
        now = time.time()

        for host_ip, current in current_scan.items():
            previous = store_get(host_ip)
            if previous is None:
                events.append(self._new_host(target, host_ip, current, now))
            else:
                events.extend(self._diff_host(target, host_ip, previous, current, now))

        for host_ip in known_ips_in_scope:
            if host_ip in current_scan:
                continue
            previous = store_get(host_ip)
            if previous is not None and previous.is_up:
                events.append(self._host_down(target, host_ip, previous, now))

        return [
            e for e in events
            if _SEVERITY_ORDER.get(e.severity, 0) >= self._min_severity
        ]

    # ------------------------------------------------------------------
    # Event constructors
    # ------------------------------------------------------------------

    def _new_host(
        self, target: str, host_ip: str, current: HostState, now: float
    ) -> ChangeEvent:
        open_ports = sorted(k for k, v in current.ports.items() if v.state == "open")
        return ChangeEvent(
            timestamp=now,
            target=target,
            host_ip=host_ip,
            change_type="NEW_HOST",
            severity="warning",
            previous=None,
            current=f"{len(open_ports)} open ports: {', '.join(open_ports)}",
            extra={"hostnames": current.hostnames, "open_ports": open_ports},
        )

    def _host_down(
        self, target: str, host_ip: str, previous: HostState, now: float
    ) -> ChangeEvent:
        return ChangeEvent(
            timestamp=now,
            target=target,
            host_ip=host_ip,
            change_type="HOST_DOWN",
            severity="critical",
            previous="up",
            current="down",
            extra={
                "last_seen": previous.timestamp,
                "last_open_ports": sorted(
                    k for k, v in previous.ports.items() if v.state == "open"
                ),
            },
        )

    def _diff_host(
        self,
        target: str,
        host_ip: str,
        previous: HostState,
        current: HostState,
        now: float,
    ) -> List[ChangeEvent]:
        events: List[ChangeEvent] = []

        prev_open: Set[str] = {k for k, v in previous.ports.items() if v.state == "open"}
        curr_open: Set[str] = {k for k, v in current.ports.items() if v.state == "open"}

        for port in sorted(curr_open - prev_open):
            info = current.ports[port]
            events.append(ChangeEvent(
                timestamp=now, target=target, host_ip=host_ip,
                change_type="PORT_OPENED", severity="critical",
                port=port,
                previous=None,
                current=_format_service(info),
            ))

        for port in sorted(prev_open - curr_open):
            info = previous.ports[port]
            events.append(ChangeEvent(
                timestamp=now, target=target, host_ip=host_ip,
                change_type="PORT_CLOSED", severity="info",
                port=port,
                previous=_format_service(info),
                current=None,
            ))

        for port in sorted(curr_open & prev_open):
            events.extend(
                self._diff_port(
                    target, host_ip, port,
                    previous.ports[port], current.ports[port], now,
                )
            )

        events.extend(
            self._diff_http_headers(target, host_ip, previous, current, now)
        )

        return events

    def _diff_port(
        self,
        target: str,
        host_ip: str,
        port: str,
        prev: PortInfo,
        curr: PortInfo,
        now: float,
    ) -> List[ChangeEvent]:
        events = []

        if prev.service != curr.service and (prev.service or curr.service):
            events.append(ChangeEvent(
                timestamp=now, target=target, host_ip=host_ip,
                change_type="SERVICE_CHANGED", severity="warning",
                port=port,
                previous=prev.service or None,
                current=curr.service or None,
            ))

        prev_ver = f"{prev.product} {prev.version}".strip()
        curr_ver = f"{curr.product} {curr.version}".strip()
        if prev_ver != curr_ver and (prev_ver or curr_ver):
            events.append(ChangeEvent(
                timestamp=now, target=target, host_ip=host_ip,
                change_type="VERSION_CHANGED", severity="info",
                port=port,
                previous=prev_ver or None,
                current=curr_ver or None,
            ))

        if prev.banner != curr.banner and (prev.banner or curr.banner):
            events.append(ChangeEvent(
                timestamp=now, target=target, host_ip=host_ip,
                change_type="BANNER_CHANGED", severity="info",
                port=port,
                previous=prev.banner or None,
                current=curr.banner or None,
            ))

        return events

    def _diff_http_headers(
        self,
        target: str,
        host_ip: str,
        previous: HostState,
        current: HostState,
        now: float,
    ) -> List[ChangeEvent]:
        events = []
        all_labels = set(previous.http_headers) | set(current.http_headers)

        for label in sorted(all_labels):
            prev_hdrs = previous.http_headers.get(label, {})
            curr_hdrs = current.http_headers.get(label, {})

            for hdr in sorted(set(prev_hdrs) | set(curr_hdrs)):
                if hdr.startswith("_"):
                    continue  # skip internal tracking keys (e.g. _status_code)
                pv = prev_hdrs.get(hdr)
                cv = curr_hdrs.get(hdr)
                if pv != cv:
                    events.append(ChangeEvent(
                        timestamp=now, target=target, host_ip=host_ip,
                        change_type="HTTP_HEADER_CHANGED", severity="info",
                        port=label,
                        previous=pv,
                        current=cv,
                        extra={"header": hdr},
                    ))

        return events


def _format_service(info: PortInfo) -> str:
    parts = [info.service, info.product, info.version, info.extrainfo]
    return " ".join(p for p in parts if p).strip() or "unknown"
