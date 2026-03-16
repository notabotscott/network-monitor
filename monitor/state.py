from __future__ import annotations

import json
import logging
import os
import re
from abc import ABC, abstractmethod
from typing import List, Optional

from .dns import DnsRecord
from .scanner import HostState

logger = logging.getLogger(__name__)

_SAFE_RE = re.compile(r"[^a-zA-Z0-9\-_]")


def _ip_to_filename(ip: str) -> str:
    """Sanitize an IP/hostname to a safe filename."""
    return _SAFE_RE.sub("_", ip) + ".json"


def _fqdn_to_filename(fqdn: str) -> str:
    """Sanitize an FQDN to a safe filename, prefixed to avoid collisions with IP files."""
    return "_dns_" + _SAFE_RE.sub("_", fqdn.rstrip(".").lower()) + ".json"


class StateStore(ABC):
    """Abstract key-value store for host and DNS state."""

    @abstractmethod
    def get(self, host_ip: str) -> Optional[HostState]:
        """Return the last known HostState for host_ip, or None."""

    @abstractmethod
    def put(self, host_ip: str, state: HostState) -> None:
        """Persist the current HostState for host_ip."""

    @abstractmethod
    def list_known_hosts(self) -> List[str]:
        """Return all host IPs currently in the store."""

    @abstractmethod
    def get_dns(self, fqdn: str) -> Optional[DnsRecord]:
        """Return the last known DnsRecord for fqdn, or None."""

    @abstractmethod
    def put_dns(self, fqdn: str, record: DnsRecord) -> None:
        """Persist the current DnsRecord for fqdn."""


class LocalStateStore(StateStore):
    """
    Stores one JSON file per host under a local directory.
    Writes are atomic (write-then-rename) to survive mid-write crashes.
    """

    def __init__(self, base_dir: str) -> None:
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)

    def _path(self, host_ip: str) -> str:
        return os.path.join(self.base_dir, _ip_to_filename(host_ip))

    def get(self, host_ip: str) -> Optional[HostState]:
        path = self._path(host_ip)
        if not os.path.exists(path):
            return None
        try:
            with open(path) as f:
                return HostState.from_dict(json.load(f))
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning(
                "Corrupt state file %s: %s — treating as new host", path, exc
            )
            return None

    def put(self, host_ip: str, state: HostState) -> None:
        path = self._path(host_ip)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(state.to_dict(), f, indent=2)
            os.replace(tmp, path)  # atomic on POSIX
        except OSError as exc:
            logger.error("Failed to write state for %s: %s", host_ip, exc)
            raise

    def list_known_hosts(self) -> List[str]:
        hosts = []
        for fname in os.listdir(self.base_dir):
            if not fname.endswith(".json") or fname.endswith(".tmp"):
                continue
            if fname.startswith("_dns_"):
                continue
            path = os.path.join(self.base_dir, fname)
            try:
                with open(path) as f:
                    d = json.load(f)
                hosts.append(d["ip"])
            except Exception:
                pass
        return hosts

    def get_dns(self, fqdn: str) -> Optional[DnsRecord]:
        path = os.path.join(self.base_dir, _fqdn_to_filename(fqdn))
        if not os.path.exists(path):
            return None
        try:
            with open(path) as f:
                return DnsRecord.from_dict(json.load(f))
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("Corrupt DNS state file %s: %s", path, exc)
            return None

    def put_dns(self, fqdn: str, record: DnsRecord) -> None:
        path = os.path.join(self.base_dir, _fqdn_to_filename(fqdn))
        tmp = path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(record.to_dict(), f, indent=2)
            os.replace(tmp, path)
        except OSError as exc:
            logger.error("Failed to write DNS state for %s: %s", fqdn, exc)
            raise


class GCSStateStore(StateStore):
    """
    Stores one JSON blob per host in a GCS bucket.
    Authentication uses Application Default Credentials (Workload Identity on Cloud Run).
    """

    def __init__(self, bucket_name: str, prefix: str = "network-monitor/state") -> None:
        from google.cloud import storage  # lazy import
        self._client = storage.Client()
        self._bucket = self._client.bucket(bucket_name)
        self._prefix = prefix.rstrip("/")

    def _blob_name(self, host_ip: str) -> str:
        return f"{self._prefix}/{_ip_to_filename(host_ip)}"

    def get(self, host_ip: str) -> Optional[HostState]:
        blob = self._bucket.blob(self._blob_name(host_ip))
        try:
            data = blob.download_as_text()
            return HostState.from_dict(json.loads(data))
        except Exception as exc:
            if "404" in str(exc) or "NotFound" in type(exc).__name__:
                return None
            logger.warning(
                "GCS read error for %s: %s — treating as new host", host_ip, exc
            )
            return None

    def put(self, host_ip: str, state: HostState) -> None:
        blob = self._bucket.blob(self._blob_name(host_ip))
        try:
            blob.upload_from_string(
                json.dumps(state.to_dict(), indent=2),
                content_type="application/json",
            )
        except Exception as exc:
            logger.error("GCS write error for %s: %s", host_ip, exc)
            raise

    def list_known_hosts(self) -> List[str]:
        hosts = []
        prefix = self._prefix + "/"
        for blob in self._bucket.list_blobs(prefix=prefix):
            if blob.name.rsplit("/", 1)[-1].startswith("_dns_"):
                continue
            try:
                d = json.loads(blob.download_as_text())
                hosts.append(d["ip"])
            except Exception:
                pass
        return hosts

    def get_dns(self, fqdn: str) -> Optional[DnsRecord]:
        blob = self._bucket.blob(f"{self._prefix}/{_fqdn_to_filename(fqdn)}")
        try:
            return DnsRecord.from_dict(json.loads(blob.download_as_text()))
        except Exception as exc:
            if "404" in str(exc) or "NotFound" in type(exc).__name__:
                return None
            logger.warning("GCS DNS read error for %s: %s", fqdn, exc)
            return None

    def put_dns(self, fqdn: str, record: DnsRecord) -> None:
        blob = self._bucket.blob(f"{self._prefix}/{_fqdn_to_filename(fqdn)}")
        try:
            blob.upload_from_string(
                json.dumps(record.to_dict(), indent=2),
                content_type="application/json",
            )
        except Exception as exc:
            logger.error("GCS DNS write error for %s: %s", fqdn, exc)
            raise


def create_store(
    backend: str,
    local_dir: str,
    gcs_bucket: str,
    gcs_prefix: str,
) -> StateStore:
    if backend == "gcs":
        if not gcs_bucket:
            raise ValueError(
                "MONITOR_STATE_GCS_BUCKET must be set when using the GCS backend."
            )
        return GCSStateStore(bucket_name=gcs_bucket, prefix=gcs_prefix)
    return LocalStateStore(base_dir=local_dir)
