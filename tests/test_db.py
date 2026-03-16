"""
Database round-trip and integration tests using an in-memory SQLite database.
No network, no nmap, no real DNS — pure data layer.
"""
from __future__ import annotations

import time
from typing import Optional

import pytest

from monitor.db import Database
from monitor.differ import ChangeEvent, Differ
from monitor.dns import DnsRecord
from monitor.main import diff_phase, scan_phase
from monitor.scanner import HostState, PortInfo


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path):
    d = Database(f"sqlite:///{tmp_path}/test.db", client_id="acme")
    yield d
    d.close()


@pytest.fixture
def db_url(tmp_path):
    """Yields just the URL so tests can open multiple clients against the same file."""
    return f"sqlite:///{tmp_path}/shared.db"


def host(ip: str, ports: dict = None, http: dict = None, is_up: bool = True) -> HostState:
    port_infos = {}
    for key, val in (ports or {}).items():
        if isinstance(val, str):
            port_infos[key] = PortInfo(state=val)
        else:
            state, service, product, version = (list(val) + ["", "", ""])[:4]
            port_infos[key] = PortInfo(state=state, service=service, product=product, version=version)
    return HostState(
        ip=ip, hostnames=[], timestamp=time.time(),
        ports=port_infos, http_headers=http or {}, is_up=is_up,
    )


def dns(fqdn: str, a=None, cname=None, failed=False) -> DnsRecord:
    return DnsRecord(
        fqdn=fqdn, timestamp=time.time(),
        a_records=sorted(a or []), aaaa_records=[],
        cname=cname, ttl=300, resolution_failed=failed,
    )


# ---------------------------------------------------------------------------
# Scan lifecycle
# ---------------------------------------------------------------------------

class TestScanLifecycle:
    def test_begin_returns_incrementing_ids(self, db):
        id1 = db.begin_scan(["10.0.0.1"])
        id2 = db.begin_scan(["10.0.0.2"])
        assert id2 > id1

    def test_complete_scan_sets_status(self, db):
        sid = db.begin_scan(["10.0.0.1"])
        db.complete_scan(sid)
        assert db.get_latest_completed_scan_id() == sid

    def test_failed_scan_not_returned_as_latest(self, db):
        sid = db.begin_scan(["10.0.0.1"])
        db.fail_scan(sid)
        assert db.get_latest_completed_scan_id() is None

    def test_running_scan_not_returned_as_latest(self, db):
        db.begin_scan(["10.0.0.1"])  # never completed
        assert db.get_latest_completed_scan_id() is None

    def test_get_scan_targets(self, db):
        targets = ["10.0.0.1", "example.com"]
        sid = db.begin_scan(targets)
        assert db.get_scan_targets(sid) == targets


# ---------------------------------------------------------------------------
# Host snapshot round-trips
# ---------------------------------------------------------------------------

class TestHostSnapshots:
    def test_roundtrip_basic(self, db):
        sid = db.begin_scan(["10.0.0.1"])
        h = host("10.0.0.1", {"22/tcp": ("open", "ssh", "OpenSSH", "8.2")})
        db.write_host_snapshot(sid, h)
        db.complete_scan(sid)

        hosts = db.get_hosts_in_scan(sid)
        assert "10.0.0.1" in hosts
        assert hosts["10.0.0.1"].ports["22/tcp"].service == "ssh"
        assert hosts["10.0.0.1"].ports["22/tcp"].product == "OpenSSH"
        assert hosts["10.0.0.1"].ports["22/tcp"].version == "8.2"

    def test_roundtrip_multiple_ports(self, db):
        sid = db.begin_scan(["10.0.0.1"])
        h = host("10.0.0.1", {
            "22/tcp": ("open", "ssh", "OpenSSH", "8.2"),
            "80/tcp": ("open", "http", "nginx", "1.24"),
            "443/tcp": ("open", "https", "nginx", "1.24"),
        })
        db.write_host_snapshot(sid, h)
        db.complete_scan(sid)

        loaded = db.get_hosts_in_scan(sid)["10.0.0.1"]
        assert len(loaded.ports) == 3
        assert loaded.ports["80/tcp"].product == "nginx"

    def test_roundtrip_banner(self, db):
        sid = db.begin_scan(["10.0.0.1"])
        h = host("10.0.0.1")
        h.ports["22/tcp"] = PortInfo(state="open", service="ssh", banner="SSH-2.0-OpenSSH_8.9p1")
        db.write_host_snapshot(sid, h)
        db.complete_scan(sid)

        loaded = db.get_hosts_in_scan(sid)["10.0.0.1"]
        assert loaded.ports["22/tcp"].banner == "SSH-2.0-OpenSSH_8.9p1"

    def test_roundtrip_http_headers(self, db):
        sid = db.begin_scan(["10.0.0.1"])
        h = host("10.0.0.1", http={"80/http": {"Server": "nginx/1.24", "_status_code": "200"}})
        db.write_host_snapshot(sid, h)
        db.complete_scan(sid)

        loaded = db.get_hosts_in_scan(sid)["10.0.0.1"]
        assert loaded.http_headers["80/http"]["Server"] == "nginx/1.24"

    def test_roundtrip_is_up_false(self, db):
        sid = db.begin_scan(["10.0.0.1"])
        h = host("10.0.0.1", is_up=False)
        db.write_host_snapshot(sid, h)
        db.complete_scan(sid)

        loaded = db.get_hosts_in_scan(sid)["10.0.0.1"]
        assert loaded.is_up is False

    def test_multiple_hosts_loaded_in_bulk(self, db):
        sid = db.begin_scan(["10.0.0.0/24"])
        for i in range(1, 6):
            db.write_host_snapshot(sid, host(f"10.0.0.{i}", {"80/tcp": "open"}))
        db.complete_scan(sid)

        hosts = db.get_hosts_in_scan(sid)
        assert len(hosts) == 5


# ---------------------------------------------------------------------------
# get_previous_host_state
# ---------------------------------------------------------------------------

class TestPreviousHostState:
    def _two_scans(self, db, ip, ports1, ports2):
        sid1 = db.begin_scan([ip])
        db.write_host_snapshot(sid1, host(ip, ports1))
        db.complete_scan(sid1)

        sid2 = db.begin_scan([ip])
        db.write_host_snapshot(sid2, host(ip, ports2))
        db.complete_scan(sid2)
        return sid1, sid2

    def test_returns_state_from_prior_scan(self, db):
        sid1, sid2 = self._two_scans(
            db, "10.0.0.1",
            {"22/tcp": ("open", "ssh", "OpenSSH", "8.2")},
            {"22/tcp": ("open", "ssh", "OpenSSH", "9.0")},
        )
        prev = db.get_previous_host_state("10.0.0.1", before_scan_id=sid2)
        assert prev is not None
        assert prev.ports["22/tcp"].version == "8.2"

    def test_returns_none_for_unknown_ip(self, db):
        sid = db.begin_scan(["10.0.0.1"])
        db.complete_scan(sid)
        assert db.get_previous_host_state("10.0.0.99", before_scan_id=sid) is None

    def test_returns_none_when_only_one_scan(self, db):
        sid = db.begin_scan(["10.0.0.1"])
        db.write_host_snapshot(sid, host("10.0.0.1", {"80/tcp": "open"}))
        db.complete_scan(sid)
        assert db.get_previous_host_state("10.0.0.1", before_scan_id=sid) is None

    def test_does_not_return_current_scan(self, db):
        sid = db.begin_scan(["10.0.0.1"])
        db.write_host_snapshot(sid, host("10.0.0.1"))
        db.complete_scan(sid)
        # before_scan_id=sid means strictly < sid, so same scan should not be returned
        assert db.get_previous_host_state("10.0.0.1", before_scan_id=sid) is None


# ---------------------------------------------------------------------------
# DNS snapshot round-trips
# ---------------------------------------------------------------------------

class TestDnsSnapshots:
    def test_roundtrip(self, db):
        sid = db.begin_scan(["example.com"])
        db.write_dns_snapshot(sid, dns("example.com", a=["1.2.3.4"], cname="cdn.example.net"))
        db.complete_scan(sid)

        results = db.get_dns_in_scan(sid)
        assert "example.com" in results
        assert results["example.com"].a_records == ["1.2.3.4"]
        assert results["example.com"].cname == "cdn.example.net"

    def test_previous_dns_record(self, db):
        sid1 = db.begin_scan(["example.com"])
        db.write_dns_snapshot(sid1, dns("example.com", a=["1.2.3.4"]))
        db.complete_scan(sid1)

        sid2 = db.begin_scan(["example.com"])
        db.write_dns_snapshot(sid2, dns("example.com", a=["9.9.9.9"]))
        db.complete_scan(sid2)

        prev = db.get_previous_dns_record("example.com", before_scan_id=sid2)
        assert prev.a_records == ["1.2.3.4"]

    def test_failed_resolution_stored(self, db):
        sid = db.begin_scan(["gone.example.com"])
        db.write_dns_snapshot(sid, dns("gone.example.com", failed=True))
        db.complete_scan(sid)

        results = db.get_dns_in_scan(sid)
        assert results["gone.example.com"].resolution_failed is True


# ---------------------------------------------------------------------------
# change_events persistence
# ---------------------------------------------------------------------------

class TestChangeEvents:
    def test_write_and_implicit_read(self, db):
        sid = db.begin_scan(["10.0.0.1"])
        db.complete_scan(sid)
        events = [
            ChangeEvent(
                timestamp=time.time(), target="10.0.0.1", host_ip="10.0.0.1",
                change_type="PORT_OPENED", severity="critical",
                port="3306/tcp", previous=None, current="mysql MySQL 8.0",
            )
        ]
        db.write_change_events(sid, events)
        # Verify row exists
        rows = db._conn.fetchall("SELECT change_type, severity FROM change_events WHERE scan_id=?", (sid,))
        assert len(rows) == 1
        assert rows[0][0] == "PORT_OPENED"
        assert rows[0][1] == "critical"

    def test_empty_events_no_error(self, db):
        sid = db.begin_scan(["10.0.0.1"])
        db.complete_scan(sid)
        db.write_change_events(sid, [])  # should not raise


# ---------------------------------------------------------------------------
# diff_phase integration (end-to-end through DB)
# ---------------------------------------------------------------------------

class TestDiffPhaseIntegration:
    def _differ(self):
        return Differ(alert_min_severity="info")

    def _config(self, targets):
        from monitor.config import Config
        return Config(targets=targets, log_changes_only=True)

    def test_new_host_on_first_scan(self, db):
        # On the very first scan a NEW_HOST event fires for each discovered host —
        # this is intentional: the operator learns what the baseline surface looks like.
        config = self._config(["10.0.0.1"])
        sid = db.begin_scan(["10.0.0.1"])
        db.write_host_snapshot(sid, host("10.0.0.1", {"22/tcp": ("open", "ssh", "OpenSSH", "8.2")}))
        db.complete_scan(sid)

        events = diff_phase(config, db, self._differ(), scan_id=sid)
        assert any(e.change_type == "NEW_HOST" and e.host_ip == "10.0.0.1" for e in events)

    def test_port_opened_detected(self, db):
        config = self._config(["10.0.0.1"])

        sid1 = db.begin_scan(["10.0.0.1"])
        db.write_host_snapshot(sid1, host("10.0.0.1", {"22/tcp": ("open", "ssh", "OpenSSH", "8.2")}))
        db.complete_scan(sid1)

        sid2 = db.begin_scan(["10.0.0.1"])
        db.write_host_snapshot(sid2, host("10.0.0.1", {
            "22/tcp": ("open", "ssh", "OpenSSH", "8.2"),
            "3306/tcp": ("open", "mysql", "MySQL", "8.0"),
        }))
        db.complete_scan(sid2)

        events = diff_phase(config, db, self._differ(), scan_id=sid2)
        assert any(e.change_type == "PORT_OPENED" and e.port == "3306/tcp" for e in events)

    def test_version_change_detected(self, db):
        config = self._config(["10.0.0.1"])

        sid1 = db.begin_scan(["10.0.0.1"])
        db.write_host_snapshot(sid1, host("10.0.0.1", {"80/tcp": ("open", "http", "nginx", "1.18.0")}))
        db.complete_scan(sid1)

        sid2 = db.begin_scan(["10.0.0.1"])
        db.write_host_snapshot(sid2, host("10.0.0.1", {"80/tcp": ("open", "http", "nginx", "1.24.0")}))
        db.complete_scan(sid2)

        events = diff_phase(config, db, self._differ(), scan_id=sid2)
        vc = [e for e in events if e.change_type == "VERSION_CHANGED"]
        assert len(vc) == 1
        assert vc[0].previous == "nginx 1.18.0"
        assert vc[0].current == "nginx 1.24.0"

    def test_host_down_detected(self, db):
        config = self._config(["10.0.0.1"])

        sid1 = db.begin_scan(["10.0.0.1"])
        db.write_host_snapshot(sid1, host("10.0.0.1", {"22/tcp": "open"}))
        db.complete_scan(sid1)

        # Second scan: host did not respond — no snapshot written for it.
        # diff_phase detects HOST_DOWN because the IP is in known_ips_in_scope
        # but absent from get_hosts_in_scan(sid2).
        sid2 = db.begin_scan(["10.0.0.1"])
        db.complete_scan(sid2)

        events = diff_phase(config, db, self._differ(), scan_id=sid2)
        assert any(e.change_type == "HOST_DOWN" for e in events)

    def test_change_events_written_to_db(self, db):
        config = self._config(["10.0.0.1"])

        sid1 = db.begin_scan(["10.0.0.1"])
        db.write_host_snapshot(sid1, host("10.0.0.1", {"22/tcp": ("open", "ssh", "OpenSSH", "8.2")}))
        db.complete_scan(sid1)

        sid2 = db.begin_scan(["10.0.0.1"])
        db.write_host_snapshot(sid2, host("10.0.0.1", {
            "22/tcp": ("open", "ssh", "OpenSSH", "8.2"),
            "8080/tcp": ("open", "http", "Apache", "2.4"),
        }))
        db.complete_scan(sid2)

        diff_phase(config, db, self._differ(), scan_id=sid2)

        rows = db._conn.fetchall(
            "SELECT change_type FROM change_events WHERE scan_id=?", (sid2,)
        )
        assert any(r[0] == "PORT_OPENED" for r in rows)

    def test_no_completed_scans_returns_empty(self, db):
        config = self._config(["10.0.0.1"])
        events = diff_phase(config, db, self._differ())
        assert events == []


# ---------------------------------------------------------------------------
# Client isolation
# ---------------------------------------------------------------------------

class TestClientIsolation:
    """Two clients share one database file — their data must never cross."""

    def test_scans_are_isolated(self, db_url):
        acme = Database(db_url, client_id="acme")
        globex = Database(db_url, client_id="globex")

        sid_a = acme.begin_scan(["10.0.0.1"])
        acme.complete_scan(sid_a)

        sid_g = globex.begin_scan(["10.0.0.2"])
        globex.complete_scan(sid_g)

        assert acme.get_latest_completed_scan_id() == sid_a
        assert globex.get_latest_completed_scan_id() == sid_g

        acme.close()
        globex.close()

    def test_host_snapshots_are_isolated(self, db_url):
        acme = Database(db_url, client_id="acme")
        globex = Database(db_url, client_id="globex")

        # Both clients scan the same IP with different open ports
        sid_a = acme.begin_scan(["10.0.0.1"])
        acme.write_host_snapshot(sid_a, host("10.0.0.1", {"22/tcp": ("open", "ssh", "OpenSSH", "8.0")}))
        acme.complete_scan(sid_a)

        sid_g = globex.begin_scan(["10.0.0.1"])
        globex.write_host_snapshot(sid_g, host("10.0.0.1", {"3389/tcp": ("open", "msrdp", "", "")}))
        globex.complete_scan(sid_g)

        acme_hosts = acme.get_hosts_in_scan(sid_a)
        globex_hosts = globex.get_hosts_in_scan(sid_g)

        assert "22/tcp" in acme_hosts["10.0.0.1"].ports
        assert "3389/tcp" not in acme_hosts["10.0.0.1"].ports

        assert "3389/tcp" in globex_hosts["10.0.0.1"].ports
        assert "22/tcp" not in globex_hosts["10.0.0.1"].ports

        acme.close()
        globex.close()

    def test_previous_host_state_does_not_cross_clients(self, db_url):
        acme = Database(db_url, client_id="acme")
        globex = Database(db_url, client_id="globex")

        # acme scanned 10.0.0.5 previously; globex never has
        sid_a = acme.begin_scan(["10.0.0.5"])
        acme.write_host_snapshot(sid_a, host("10.0.0.5", {"80/tcp": "open"}))
        acme.complete_scan(sid_a)

        sid_g = globex.begin_scan(["10.0.0.5"])
        globex.complete_scan(sid_g)

        # globex should see no previous state for 10.0.0.5
        assert globex.get_previous_host_state("10.0.0.5", before_scan_id=sid_g) is None

        acme.close()
        globex.close()

    def test_dns_snapshots_are_isolated(self, db_url):
        acme = Database(db_url, client_id="acme")
        globex = Database(db_url, client_id="globex")

        sid_a = acme.begin_scan(["example.com"])
        acme.write_dns_snapshot(sid_a, dns("example.com", a=["1.1.1.1"]))
        acme.complete_scan(sid_a)

        sid_g = globex.begin_scan(["example.com"])
        globex.write_dns_snapshot(sid_g, dns("example.com", a=["2.2.2.2"]))
        globex.complete_scan(sid_g)

        acme_dns = acme.get_dns_in_scan(sid_a)
        globex_dns = globex.get_dns_in_scan(sid_g)

        assert acme_dns["example.com"].a_records == ["1.1.1.1"]
        assert globex_dns["example.com"].a_records == ["2.2.2.2"]

        # globex should not see acme's DNS history
        assert globex.get_previous_dns_record("example.com", before_scan_id=sid_g) is None

        acme.close()
        globex.close()

    def test_change_events_are_isolated(self, db_url):
        acme = Database(db_url, client_id="acme")
        globex = Database(db_url, client_id="globex")

        sid_a = acme.begin_scan(["10.0.0.1"])
        acme.complete_scan(sid_a)
        acme.write_change_events(sid_a, [
            ChangeEvent(
                timestamp=0, target="10.0.0.1", host_ip="10.0.0.1",
                change_type="PORT_OPENED", severity="critical", port="22/tcp",
            )
        ])

        sid_g = globex.begin_scan(["10.0.0.1"])
        globex.complete_scan(sid_g)

        # globex's change_events table should be empty
        rows = globex._conn.fetchall(
            "SELECT id FROM change_events WHERE client_id='globex'"
        )
        assert rows == []

        acme.close()
        globex.close()

    def test_client_id_required(self, db_url):
        with pytest.raises(ValueError):
            Database(db_url, client_id="")
