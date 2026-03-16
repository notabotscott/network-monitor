from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver

logger = logging.getLogger(__name__)


@dataclass
class DnsRecord:
    fqdn: str
    timestamp: float
    a_records: List[str]        # sorted IPv4 addresses
    aaaa_records: List[str]     # sorted IPv6 addresses
    cname: Optional[str]        # canonical name after following CNAME chain
    ttl: Optional[int]          # minimum TTL across A records (None if resolution failed)
    resolution_failed: bool = False

    def to_dict(self) -> dict:
        return {
            "fqdn": self.fqdn,
            "timestamp": self.timestamp,
            "a_records": self.a_records,
            "aaaa_records": self.aaaa_records,
            "cname": self.cname,
            "ttl": self.ttl,
            "resolution_failed": self.resolution_failed,
        }

    @classmethod
    def from_dict(cls, d: dict) -> DnsRecord:
        return cls(
            fqdn=d["fqdn"],
            timestamp=d.get("timestamp", 0.0),
            a_records=d.get("a_records", []),
            aaaa_records=d.get("aaaa_records", []),
            cname=d.get("cname"),
            ttl=d.get("ttl"),
            resolution_failed=d.get("resolution_failed", False),
        )

    @classmethod
    def failed(cls, fqdn: str) -> DnsRecord:
        return cls(
            fqdn=fqdn,
            timestamp=time.time(),
            a_records=[],
            aaaa_records=[],
            cname=None,
            ttl=None,
            resolution_failed=True,
        )


class FqdnResolver:
    def __init__(self, timeout: float = 5.0, nameservers: Optional[List[str]] = None) -> None:
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout
        if nameservers:
            self._resolver.nameservers = nameservers

    def resolve(self, fqdn: str) -> DnsRecord:
        """Resolve A, AAAA records and follow any CNAME chain for fqdn."""
        a_records: List[str] = []
        aaaa_records: List[str] = []
        cname: Optional[str] = None
        min_ttl: Optional[int] = None

        # Resolve A records (also reveals CNAME if present)
        try:
            answer = self._resolver.resolve(fqdn, "A")
            # Canonical name after CNAME chain (may equal fqdn if no CNAME)
            canonical = str(answer.canonical_name).rstrip(".")
            if canonical.lower() != fqdn.lower():
                cname = canonical

            for rdata in answer:
                a_records.append(str(rdata.address))
            if answer.rrset is not None and answer.rrset.ttl is not None:
                min_ttl = answer.rrset.ttl

        except dns.resolver.NXDOMAIN:
            logger.warning("DNS NXDOMAIN for %s", fqdn)
            return DnsRecord.failed(fqdn)
        except dns.resolver.NoAnswer:
            # No A records — could still have AAAA; continue
            pass
        except dns.exception.DNSException as exc:
            logger.warning("DNS resolution failed for %s: %s", fqdn, exc)
            return DnsRecord.failed(fqdn)

        # Resolve AAAA records
        try:
            answer6 = self._resolver.resolve(fqdn, "AAAA")
            for rdata in answer6:
                aaaa_records.append(str(rdata.address))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.DNSException as exc:
            logger.debug("AAAA resolution failed for %s: %s", fqdn, exc)

        if not a_records and not aaaa_records:
            return DnsRecord.failed(fqdn)

        return DnsRecord(
            fqdn=fqdn,
            timestamp=time.time(),
            a_records=sorted(a_records),
            aaaa_records=sorted(aaaa_records),
            cname=cname,
            ttl=min_ttl,
            resolution_failed=False,
        )

    def resolve_all(self, fqdns: List[str]) -> dict[str, DnsRecord]:
        results = {}
        for fqdn in fqdns:
            results[fqdn] = self.resolve(fqdn)
            logger.debug(
                "Resolved %s → A=%s AAAA=%s cname=%s",
                fqdn, results[fqdn].a_records, results[fqdn].aaaa_records, results[fqdn].cname,
            )
        return results


def extract_fqdns(targets: List[str]) -> List[str]:
    """Return only the FQDN entries from a targets list (excludes IPs and CIDRs)."""
    fqdns = []
    for t in targets:
        try:
            ipaddress.ip_network(t, strict=False)
        except ValueError:
            fqdns.append(t)
    return fqdns


def diff_dns(
    fqdn: str,
    previous: Optional[DnsRecord],
    current: DnsRecord,
    now: float,
) -> list:
    """
    Compare two DnsRecord objects and return a list of ChangeEvent dicts.
    Returns plain dicts to avoid a circular import with differ.py.
    Each dict has the same keys as ChangeEvent.to_dict().
    """
    events = []

    def _evt(change_type: str, severity: str, previous_val, current_val, extra=None):
        return {
            "timestamp": now,
            "target": fqdn,
            "host_ip": fqdn,
            "change_type": change_type,
            "severity": severity,
            "port": None,
            "previous": previous_val,
            "current": current_val,
            "extra": extra or {},
        }

    # ── First time seeing this FQDN ──────────────────────────────────────
    if previous is None:
        if not current.resolution_failed:
            events.append(_evt(
                "DNS_NEW_FQDN", "info",
                None,
                f"A={current.a_records} AAAA={current.aaaa_records}",
                {"a_records": current.a_records, "aaaa_records": current.aaaa_records,
                 "cname": current.cname},
            ))
        return events

    # ── Previously failed, now resolves ──────────────────────────────────
    if previous.resolution_failed and not current.resolution_failed:
        events.append(_evt(
            "DNS_RESOLUTION_RESTORED", "warning",
            "unresolvable",
            f"A={current.a_records}",
            {"a_records": current.a_records},
        ))
        return events

    # ── Now failing, was resolving ────────────────────────────────────────
    if not previous.resolution_failed and current.resolution_failed:
        events.append(_evt(
            "DNS_RESOLUTION_FAILED", "warning",
            f"A={previous.a_records}",
            "unresolvable",
            {"last_a_records": previous.a_records},
        ))
        return events

    # ── Both resolved — compare A records ────────────────────────────────
    prev_a = set(previous.a_records)
    curr_a = set(current.a_records)

    if prev_a and curr_a and prev_a.isdisjoint(curr_a):
        # Complete IP swap — strongest hijack signal
        events.append(_evt(
            "DNS_RECORD_CHANGED", "critical",
            ", ".join(sorted(prev_a)),
            ", ".join(sorted(curr_a)),
            {"previous_ips": sorted(prev_a), "current_ips": sorted(curr_a)},
        ))
    else:
        for ip in sorted(curr_a - prev_a):
            events.append(_evt(
                "DNS_IP_ADDED", "info",
                None, ip,
                {"ip": ip, "all_current": sorted(curr_a)},
            ))
        for ip in sorted(prev_a - curr_a):
            events.append(_evt(
                "DNS_IP_REMOVED", "warning",
                ip, None,
                {"ip": ip, "all_current": sorted(curr_a)},
            ))

    # ── CNAME changes ────────────────────────────────────────────────────
    if previous.cname != current.cname:
        events.append(_evt(
            "DNS_CNAME_CHANGED", "warning",
            previous.cname, current.cname,
        ))

    # ── AAAA changes (informational) ─────────────────────────────────────
    prev_aaaa = set(previous.aaaa_records)
    curr_aaaa = set(current.aaaa_records)

    if prev_aaaa and curr_aaaa and prev_aaaa.isdisjoint(curr_aaaa):
        events.append(_evt(
            "DNS_AAAA_CHANGED", "info",
            ", ".join(sorted(prev_aaaa)),
            ", ".join(sorted(curr_aaaa)),
            {"previous_ips": sorted(prev_aaaa), "current_ips": sorted(curr_aaaa)},
        ))

    return events
