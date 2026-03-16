"""Unit tests for DNS change detection (no network calls needed)."""
from __future__ import annotations

import time

import pytest

from monitor.dns import DnsRecord, diff_dns, extract_fqdns


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def record(fqdn: str, a=None, aaaa=None, cname=None, ttl=300, failed=False) -> DnsRecord:
    return DnsRecord(
        fqdn=fqdn,
        timestamp=time.time(),
        a_records=sorted(a or []),
        aaaa_records=sorted(aaaa or []),
        cname=cname,
        ttl=ttl,
        resolution_failed=failed,
    )


def do_diff(prev, curr, fqdn="example.com"):
    return diff_dns(fqdn, prev, curr, time.time())


def types(events):
    return [e["change_type"] for e in events]


# ---------------------------------------------------------------------------
# First time
# ---------------------------------------------------------------------------

class TestNewFqdn:
    def test_new_fqdn_emits_dns_new_fqdn(self):
        curr = record("example.com", a=["1.2.3.4"])
        events = do_diff(None, curr)
        assert types(events) == ["DNS_NEW_FQDN"]
        assert events[0]["severity"] == "info"

    def test_new_fqdn_failed_emits_nothing(self):
        curr = record("example.com", failed=True)
        events = do_diff(None, curr)
        assert events == []

    def test_new_fqdn_extra_contains_records(self):
        curr = record("example.com", a=["1.2.3.4"], aaaa=["::1"])
        events = do_diff(None, curr)
        assert events[0]["extra"]["a_records"] == ["1.2.3.4"]
        assert events[0]["extra"]["aaaa_records"] == ["::1"]


# ---------------------------------------------------------------------------
# Resolution failures / restores
# ---------------------------------------------------------------------------

class TestResolutionFailure:
    def test_starts_resolving_then_fails(self):
        prev = record("example.com", a=["1.2.3.4"])
        curr = record("example.com", failed=True)
        events = do_diff(prev, curr)
        assert types(events) == ["DNS_RESOLUTION_FAILED"]
        assert events[0]["severity"] == "warning"
        assert events[0]["extra"]["last_a_records"] == ["1.2.3.4"]

    def test_was_failed_now_resolves(self):
        prev = record("example.com", failed=True)
        curr = record("example.com", a=["1.2.3.4"])
        events = do_diff(prev, curr)
        assert types(events) == ["DNS_RESOLUTION_RESTORED"]
        assert events[0]["severity"] == "warning"

    def test_both_failed_no_event(self):
        prev = record("example.com", failed=True)
        curr = record("example.com", failed=True)
        events = do_diff(prev, curr)
        assert events == []


# ---------------------------------------------------------------------------
# A record changes
# ---------------------------------------------------------------------------

class TestARecordChanges:
    def test_complete_swap_is_critical(self):
        prev = record("example.com", a=["1.2.3.4"])
        curr = record("example.com", a=["9.9.9.9"])
        events = do_diff(prev, curr)
        assert types(events) == ["DNS_RECORD_CHANGED"]
        assert events[0]["severity"] == "critical"
        assert events[0]["previous"] == "1.2.3.4"
        assert events[0]["current"] == "9.9.9.9"

    def test_complete_swap_multiple_ips(self):
        prev = record("example.com", a=["1.2.3.4", "1.2.3.5"])
        curr = record("example.com", a=["9.9.9.9", "8.8.8.8"])
        events = do_diff(prev, curr)
        assert types(events) == ["DNS_RECORD_CHANGED"]

    def test_ip_added(self):
        prev = record("example.com", a=["1.2.3.4"])
        curr = record("example.com", a=["1.2.3.4", "1.2.3.5"])
        events = do_diff(prev, curr)
        assert types(events) == ["DNS_IP_ADDED"]
        assert events[0]["severity"] == "info"
        assert events[0]["current"] == "1.2.3.5"

    def test_ip_removed(self):
        prev = record("example.com", a=["1.2.3.4", "1.2.3.5"])
        curr = record("example.com", a=["1.2.3.4"])
        events = do_diff(prev, curr)
        assert types(events) == ["DNS_IP_REMOVED"]
        assert events[0]["severity"] == "warning"
        assert events[0]["previous"] == "1.2.3.5"

    def test_multiple_adds_and_removes(self):
        prev = record("example.com", a=["1.1.1.1", "2.2.2.2"])
        curr = record("example.com", a=["1.1.1.1", "3.3.3.3"])
        events = do_diff(prev, curr)
        change_types = set(types(events))
        assert "DNS_IP_ADDED" in change_types
        assert "DNS_IP_REMOVED" in change_types

    def test_no_change_no_events(self):
        prev = record("example.com", a=["1.2.3.4"])
        curr = record("example.com", a=["1.2.3.4"])
        events = do_diff(prev, curr)
        assert events == []

    def test_partial_overlap_not_critical(self):
        # Some IPs in common → individual add/remove events, not DNS_RECORD_CHANGED
        prev = record("example.com", a=["1.2.3.4", "1.2.3.5"])
        curr = record("example.com", a=["1.2.3.4", "1.2.3.6"])
        events = do_diff(prev, curr)
        assert "DNS_RECORD_CHANGED" not in types(events)
        assert "DNS_IP_ADDED" in types(events)
        assert "DNS_IP_REMOVED" in types(events)


# ---------------------------------------------------------------------------
# CNAME changes
# ---------------------------------------------------------------------------

class TestCnameChanges:
    def test_cname_added(self):
        prev = record("example.com", a=["1.2.3.4"], cname=None)
        curr = record("example.com", a=["1.2.3.4"], cname="cdn.example.net")
        events = do_diff(prev, curr)
        assert any(e["change_type"] == "DNS_CNAME_CHANGED" for e in events)
        cname_evt = next(e for e in events if e["change_type"] == "DNS_CNAME_CHANGED")
        assert cname_evt["previous"] is None
        assert cname_evt["current"] == "cdn.example.net"
        assert cname_evt["severity"] == "warning"

    def test_cname_changed(self):
        prev = record("example.com", a=["1.2.3.4"], cname="cdn1.example.net")
        curr = record("example.com", a=["9.9.9.9"], cname="cdn2.example.net")
        events = do_diff(prev, curr)
        assert any(e["change_type"] == "DNS_CNAME_CHANGED" for e in events)

    def test_cname_removed(self):
        prev = record("example.com", a=["1.2.3.4"], cname="cdn.example.net")
        curr = record("example.com", a=["1.2.3.4"], cname=None)
        events = do_diff(prev, curr)
        cname_evt = next((e for e in events if e["change_type"] == "DNS_CNAME_CHANGED"), None)
        assert cname_evt is not None
        assert cname_evt["previous"] == "cdn.example.net"
        assert cname_evt["current"] is None

    def test_unchanged_cname_no_event(self):
        prev = record("example.com", a=["1.2.3.4"], cname="cdn.example.net")
        curr = record("example.com", a=["1.2.3.4"], cname="cdn.example.net")
        events = do_diff(prev, curr)
        assert "DNS_CNAME_CHANGED" not in types(events)


# ---------------------------------------------------------------------------
# AAAA changes
# ---------------------------------------------------------------------------

class TestAaaaChanges:
    def test_aaaa_complete_swap(self):
        prev = record("example.com", a=["1.2.3.4"], aaaa=["2001:db8::1"])
        curr = record("example.com", a=["1.2.3.4"], aaaa=["2001:db8::2"])
        events = do_diff(prev, curr)
        assert any(e["change_type"] == "DNS_AAAA_CHANGED" for e in events)
        assert next(e for e in events if e["change_type"] == "DNS_AAAA_CHANGED")["severity"] == "info"

    def test_aaaa_partial_overlap_no_event(self):
        prev = record("example.com", a=["1.2.3.4"], aaaa=["2001:db8::1", "2001:db8::2"])
        curr = record("example.com", a=["1.2.3.4"], aaaa=["2001:db8::1", "2001:db8::3"])
        events = do_diff(prev, curr)
        assert "DNS_AAAA_CHANGED" not in types(events)


# ---------------------------------------------------------------------------
# host_ip / target fields
# ---------------------------------------------------------------------------

class TestEventFields:
    def test_host_ip_is_fqdn(self):
        curr = record("sub.example.com", a=["1.2.3.4"])
        events = do_diff(None, curr, fqdn="sub.example.com")
        assert events[0]["host_ip"] == "sub.example.com"
        assert events[0]["target"] == "sub.example.com"


# ---------------------------------------------------------------------------
# extract_fqdns helper
# ---------------------------------------------------------------------------

class TestExtractFqdns:
    def test_extracts_only_fqdns(self):
        targets = ["192.168.1.1", "10.0.0.0/24", "example.com", "sub.domain.io"]
        assert extract_fqdns(targets) == ["example.com", "sub.domain.io"]

    def test_empty_list(self):
        assert extract_fqdns([]) == []

    def test_all_ips(self):
        assert extract_fqdns(["1.2.3.4", "10.0.0.0/8"]) == []
