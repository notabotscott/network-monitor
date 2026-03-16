"""Unit tests for the change detection logic (no nmap or network needed)."""
from __future__ import annotations

import time
from typing import Optional

import pytest

from monitor.scanner import HostState, PortInfo
from monitor.differ import ChangeEvent, Differ


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_host(ip: str, ports: dict, http_headers: dict = None, is_up: bool = True) -> HostState:
    """Build a HostState from a concise dict like {"80/tcp": ("open", "http", "nginx", "1.18")}."""
    port_infos = {}
    for key, val in ports.items():
        if isinstance(val, str):
            port_infos[key] = PortInfo(state=val)
        else:
            state, service, product, version = (list(val) + ["", "", "", ""])[:4]
            port_infos[key] = PortInfo(
                state=state, service=service, product=product, version=version
            )
    return HostState(
        ip=ip,
        hostnames=[],
        timestamp=time.time(),
        ports=port_infos,
        http_headers=http_headers or {},
        is_up=is_up,
    )


def differ(min_severity: str = "info") -> Differ:
    return Differ(alert_min_severity=min_severity)


def no_state(_ip: str) -> Optional[HostState]:
    return None


# ---------------------------------------------------------------------------
# NEW_HOST
# ---------------------------------------------------------------------------

class TestNewHost:
    def test_unknown_host_emits_new_host(self):
        scan = {"1.2.3.4": make_host("1.2.3.4", {"80/tcp": ("open", "http", "nginx", "1.18")})}
        events = differ().diff("1.2.3.4", scan, {"1.2.3.4"}, no_state)
        assert len(events) == 1
        assert events[0].change_type == "NEW_HOST"
        assert events[0].host_ip == "1.2.3.4"
        assert events[0].severity == "warning"

    def test_new_host_current_lists_open_ports(self):
        scan = {"1.2.3.4": make_host("1.2.3.4", {
            "22/tcp": ("open", "ssh", "OpenSSH", "8.2"),
            "80/tcp": ("open", "http", "nginx", "1.18"),
        })}
        events = differ().diff("1.2.3.4", scan, set(), no_state)
        assert "22/tcp" in events[0].current
        assert "80/tcp" in events[0].current


# ---------------------------------------------------------------------------
# HOST_DOWN
# ---------------------------------------------------------------------------

class TestHostDown:
    def test_missing_host_emits_host_down(self):
        prev = make_host("1.2.3.4", {"22/tcp": ("open",)})
        events = differ().diff("1.2.3.0/24", {}, {"1.2.3.4"}, lambda ip: prev if ip == "1.2.3.4" else None)
        assert len(events) == 1
        assert events[0].change_type == "HOST_DOWN"
        assert events[0].severity == "critical"

    def test_already_down_host_not_re_emitted(self):
        prev = make_host("1.2.3.4", {}, is_up=False)
        events = differ().diff("1.2.3.0/24", {}, {"1.2.3.4"}, lambda ip: prev if ip == "1.2.3.4" else None)
        assert events == []

    def test_host_not_in_scope_not_marked_down(self):
        # Host 1.2.3.99 was previously known but is NOT in this scan's scope
        prev = make_host("1.2.3.99", {"80/tcp": ("open",)})
        events = differ().diff("1.2.3.4", {}, {"1.2.3.4"}, lambda ip: prev if ip == "1.2.3.99" else None)
        assert events == []


# ---------------------------------------------------------------------------
# PORT_OPENED / PORT_CLOSED
# ---------------------------------------------------------------------------

class TestPortChanges:
    def _store(self, state: HostState):
        return lambda ip: state if ip == state.ip else None

    def test_port_opened(self):
        prev = make_host("1.2.3.4", {"22/tcp": ("open",)})
        curr = make_host("1.2.3.4", {"22/tcp": ("open",), "80/tcp": ("open", "http", "nginx", "1.18")})
        events = differ().diff("1.2.3.4", {"1.2.3.4": curr}, set(), self._store(prev))
        opened = [e for e in events if e.change_type == "PORT_OPENED"]
        assert len(opened) == 1
        assert opened[0].port == "80/tcp"
        assert opened[0].severity == "critical"
        assert "nginx" in opened[0].current

    def test_port_closed(self):
        prev = make_host("1.2.3.4", {"22/tcp": ("open",), "80/tcp": ("open",)})
        curr = make_host("1.2.3.4", {"22/tcp": ("open",)})
        events = differ().diff("1.2.3.4", {"1.2.3.4": curr}, set(), self._store(prev))
        closed = [e for e in events if e.change_type == "PORT_CLOSED"]
        assert len(closed) == 1
        assert closed[0].port == "80/tcp"
        assert closed[0].severity == "info"

    def test_no_events_when_ports_unchanged(self):
        prev = make_host("1.2.3.4", {"22/tcp": ("open", "ssh", "OpenSSH", "8.2")})
        curr = make_host("1.2.3.4", {"22/tcp": ("open", "ssh", "OpenSSH", "8.2")})
        events = differ().diff("1.2.3.4", {"1.2.3.4": curr}, set(), self._store(prev))
        assert events == []


# ---------------------------------------------------------------------------
# VERSION_CHANGED / SERVICE_CHANGED / BANNER_CHANGED
# ---------------------------------------------------------------------------

class TestServiceChanges:
    def _store(self, state: HostState):
        return lambda ip: state if ip == state.ip else None

    def test_version_changed(self):
        prev = make_host("1.2.3.4", {"80/tcp": ("open", "http", "nginx", "1.18.0")})
        curr = make_host("1.2.3.4", {"80/tcp": ("open", "http", "nginx", "1.24.0")})
        events = differ().diff("1.2.3.4", {"1.2.3.4": curr}, set(), self._store(prev))
        vc = [e for e in events if e.change_type == "VERSION_CHANGED"]
        assert len(vc) == 1
        assert "1.18.0" in vc[0].previous
        assert "1.24.0" in vc[0].current
        assert vc[0].severity == "info"

    def test_service_changed(self):
        prev = make_host("1.2.3.4", {"80/tcp": ("open", "http", "nginx", "1.18")})
        curr = make_host("1.2.3.4", {"80/tcp": ("open", "https", "nginx", "1.18")})
        events = differ().diff("1.2.3.4", {"1.2.3.4": curr}, set(), self._store(prev))
        sc = [e for e in events if e.change_type == "SERVICE_CHANGED"]
        assert len(sc) == 1
        assert sc[0].severity == "warning"

    def test_banner_changed(self):
        prev = make_host("1.2.3.4", {})
        curr = make_host("1.2.3.4", {})
        prev.ports["22/tcp"] = PortInfo(state="open", service="ssh", banner="SSH-2.0-OpenSSH_8.2")
        curr.ports["22/tcp"] = PortInfo(state="open", service="ssh", banner="SSH-2.0-OpenSSH_9.0")
        events = differ().diff("1.2.3.4", {"1.2.3.4": curr}, set(), self._store(prev))
        bc = [e for e in events if e.change_type == "BANNER_CHANGED"]
        assert len(bc) == 1


# ---------------------------------------------------------------------------
# HTTP_HEADER_CHANGED
# ---------------------------------------------------------------------------

class TestHttpHeaderChanges:
    def _store(self, state: HostState):
        return lambda ip: state if ip == state.ip else None

    def test_server_header_changed(self):
        prev = make_host("1.2.3.4", {"80/tcp": ("open",)}, http_headers={
            "80/http": {"Server": "nginx/1.18.0", "_status_code": "200"}
        })
        curr = make_host("1.2.3.4", {"80/tcp": ("open",)}, http_headers={
            "80/http": {"Server": "nginx/1.24.0", "_status_code": "200"}
        })
        events = differ().diff("1.2.3.4", {"1.2.3.4": curr}, set(), self._store(prev))
        hc = [e for e in events if e.change_type == "HTTP_HEADER_CHANGED"]
        assert len(hc) == 1
        assert hc[0].extra["header"] == "Server"
        assert hc[0].previous == "nginx/1.18.0"
        assert hc[0].current == "nginx/1.24.0"

    def test_header_added(self):
        prev = make_host("1.2.3.4", {"443/tcp": ("open",)}, http_headers={
            "443/https": {"_status_code": "200"}
        })
        curr = make_host("1.2.3.4", {"443/tcp": ("open",)}, http_headers={
            "443/https": {"_status_code": "200", "Strict-Transport-Security": "max-age=31536000"}
        })
        events = differ().diff("1.2.3.4", {"1.2.3.4": curr}, set(), self._store(prev))
        hc = [e for e in events if e.change_type == "HTTP_HEADER_CHANGED"]
        assert any(e.extra["header"] == "Strict-Transport-Security" for e in hc)

    def test_no_events_when_headers_unchanged(self):
        hdrs = {"80/http": {"Server": "apache/2.4", "_status_code": "200"}}
        prev = make_host("1.2.3.4", {"80/tcp": ("open",)}, http_headers=hdrs)
        curr = make_host("1.2.3.4", {"80/tcp": ("open",)}, http_headers=hdrs)
        events = differ().diff("1.2.3.4", {"1.2.3.4": curr}, set(), self._store(prev))
        assert events == []


# ---------------------------------------------------------------------------
# Severity filtering
# ---------------------------------------------------------------------------

class TestSeverityFilter:
    def _store(self, state: HostState):
        return lambda ip: state if ip == state.ip else None

    def test_warning_filter_suppresses_info(self):
        prev = make_host("1.2.3.4", {"80/tcp": ("open", "http", "nginx", "1.18.0")})
        curr = make_host("1.2.3.4", {"80/tcp": ("open", "http", "nginx", "1.24.0")})
        d = Differ(alert_min_severity="warning")
        events = d.diff("1.2.3.4", {"1.2.3.4": curr}, set(), self._store(prev))
        # VERSION_CHANGED is info — should be filtered
        assert events == []

    def test_critical_filter_keeps_only_critical(self):
        prev = make_host("1.2.3.4", {"22/tcp": ("open",)})
        curr = make_host("1.2.3.4", {"22/tcp": ("open",), "3306/tcp": ("open", "mysql", "MySQL", "8.0")})
        d = Differ(alert_min_severity="critical")
        events = d.diff("1.2.3.4", {"1.2.3.4": curr}, set(), self._store(prev))
        assert all(e.severity == "critical" for e in events)
        assert any(e.change_type == "PORT_OPENED" for e in events)
