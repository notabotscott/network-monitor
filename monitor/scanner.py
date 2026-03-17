from __future__ import annotations

import ipaddress
import logging
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import nmap
import requests
import urllib3

from .config import Config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Service names nmap reports for HTTP/HTTPS endpoints
_HTTP_SERVICES = {"http", "http-alt", "http-proxy", "webcache"}
_HTTPS_SERVICES = {"https", "https-alt"}
# Well-known HTTP(S) port numbers used as a fallback when service name is ambiguous
_HTTP_PORTS = {80, 8080, 8000, 8008, 8888}
_HTTPS_PORTS = {443, 8443, 4443}
# Ports that use TLS but are NOT HTTP — banner grab needs ssl.wrap_socket
_TLS_NONHTTP_PORTS = {465, 636, 993, 995}

_CTRL_CHARS = re.compile(r"[^\x20-\x7e\n\r\t]")


@dataclass
class PortInfo:
    state: str       # open | closed | filtered
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: str = ""
    banner: str = ""

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extrainfo": self.extrainfo,
            "cpe": self.cpe,
            "banner": self.banner,
        }

    @classmethod
    def from_dict(cls, d: dict) -> PortInfo:
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class HostState:
    ip: str
    hostnames: List[str]
    timestamp: float
    ports: Dict[str, PortInfo]             # key: "80/tcp"
    http_headers: Dict[str, Dict[str, str]]  # key: "80/http" or "443/https"
    is_up: bool = True

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostnames": self.hostnames,
            "timestamp": self.timestamp,
            "is_up": self.is_up,
            "ports": {k: v.to_dict() for k, v in self.ports.items()},
            "http_headers": self.http_headers,
        }

    @classmethod
    def from_dict(cls, d: dict) -> HostState:
        ports = {k: PortInfo.from_dict(v) for k, v in d.get("ports", {}).items()}
        return cls(
            ip=d["ip"],
            hostnames=d.get("hostnames", []),
            timestamp=d.get("timestamp", 0.0),
            ports=ports,
            http_headers=d.get("http_headers", {}),
            is_up=d.get("is_up", True),
        )

    def make_down_copy(self) -> HostState:
        """Return a copy of this state with is_up=False and updated timestamp."""
        import copy
        s = copy.deepcopy(self)
        s.is_up = False
        s.timestamp = time.time()
        return s


def _clean_banner(data: bytes) -> Optional[str]:
    """Decode raw bytes into a printable one-line string, or None if empty."""
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    text = _CTRL_CHARS.sub(" ", text)   # replace non-printable with space
    text = re.sub(r"\s+", " ", text).strip()
    return text[:256] or None


class BannerGrabber:
    """
    Opens a raw TCP connection to each non-HTTP open port and reads the first
    bytes the server sends (the service banner).

    Works for server-speaks-first protocols: SSH, FTP, SMTP, POP3, IMAP,
    telnet, many databases, and any custom service that sends an identifying
    greeting. Silently times out for client-speaks-first protocols (MySQL
    handshake, Redis, PostgreSQL) where nmap -sV is the better source.

    All grabs run concurrently so a /24 with many open ports doesn't serialise.
    """

    def __init__(self, timeout: float = 4.0, max_bytes: int = 512) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes

    def grab(self, host: str, port: int, use_tls: bool = False) -> Optional[str]:
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as raw_sock:
                raw_sock.settimeout(self.timeout)
                if use_tls:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    conn: socket.socket = ctx.wrap_socket(raw_sock, server_hostname=host)
                else:
                    conn = raw_sock
                data = conn.recv(self.max_bytes)
            return _clean_banner(data)
        except ssl.SSLError:
            if not use_tls:
                # Plain connection got an SSL handshake — retry wrapped
                return self.grab(host, port, use_tls=True)
            return None
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def grab_all(
        self, host: str, port_keys: List[Tuple[int, bool]]
    ) -> Dict[str, Optional[str]]:
        """
        Grab banners for multiple ports concurrently.
        port_keys: list of (port_num, use_tls) tuples.
        Returns dict of "port_num" -> banner_or_None.
        """
        results: Dict[str, Optional[str]] = {}
        with ThreadPoolExecutor(max_workers=min(len(port_keys), 20)) as pool:
            futures = {
                pool.submit(self.grab, host, port_num, use_tls): str(port_num)
                for port_num, use_tls in port_keys
            }
            for future in as_completed(futures):
                key = futures[future]
                try:
                    results[key] = future.result()
                except Exception as exc:
                    logger.debug("Banner grab error for %s:%s: %s", host, key, exc)
                    results[key] = None
        return results


class Scanner:
    def __init__(self, config: Config) -> None:
        self._cfg = config
        self._nm = nmap.PortScanner()
        self._session = requests.Session()
        self._session.headers["User-Agent"] = config.http_user_agent
        self._session.max_redirects = config.http_max_redirects
        self._session.verify = False
        self._grabber = BannerGrabber(
            timeout=config.banner_grab_timeout,
            max_bytes=config.banner_grab_max_bytes,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_targets(self, targets: List[str]) -> Dict[str, HostState]:
        """
        Scan one or more targets (IP/FQDN/CIDR) and return a mapping of
        ip -> HostState for every live host discovered.
        """
        combined = " ".join(targets)

        # "top-N" is not a valid nmap -p argument; translate to --top-ports N
        # and pass it in arguments instead.
        ports_arg = self._cfg.nmap_ports
        extra_args = self._cfg.nmap_arguments
        _top = re.fullmatch(r"top-(\d+)", ports_arg.strip(), re.IGNORECASE)
        if _top:
            extra_args = f"{extra_args} --top-ports {_top.group(1)}"
            ports_arg = None  # type: ignore[assignment]

        logger.info(
            "Starting nmap scan",
            extra={
                "target": combined,
                "ports": self._cfg.nmap_ports,
                "nmap_args": extra_args,
            },
        )

        try:
            self._nm.scan(
                hosts=combined,
                ports=ports_arg,
                arguments=extra_args,
                sudo=self._cfg.nmap_sudo,
            )
        except nmap.PortScannerError as exc:
            logger.error("nmap scan failed: %s", exc)
            raise

        # Parse nmap results into (host_ip, hostnames, ports) tuples first,
        # then run banner grabbing and HTTP probing concurrently across hosts.
        live_hosts = []
        for host_ip in self._nm.all_hosts():
            host_data = self._nm[host_ip]
            if host_data.state() != "up":
                continue

            hostnames = [h["name"] for h in host_data.hostnames() if h.get("name")]
            ports: Dict[str, PortInfo] = {}

            for proto in host_data.all_protocols():
                for port_num in host_data[proto].keys():
                    port_data = host_data[proto][port_num]
                    key = f"{port_num}/{proto}"
                    ports[key] = PortInfo(
                        state=port_data.get("state", ""),
                        service=port_data.get("name", ""),
                        product=port_data.get("product", ""),
                        version=port_data.get("version", ""),
                        extrainfo=port_data.get("extrainfo", ""),
                        cpe=port_data.get("cpe", ""),
                        banner=port_data.get("script", {}).get("banner", ""),
                    )

            live_hosts.append((host_ip, hostnames, ports))

        def _post_process(args: tuple) -> HostState:
            host_ip, hostnames, ports = args
            if self._cfg.banner_grab:
                self._grab_banners(host_ip, ports)
            http_headers = self._probe_http(host_ip, ports)
            logger.debug(
                "Scanned host %s: %d open ports",
                host_ip,
                sum(1 for p in ports.values() if p.state == "open"),
            )
            return HostState(
                ip=host_ip,
                hostnames=hostnames,
                timestamp=time.time(),
                ports=ports,
                http_headers=http_headers,
                is_up=True,
            )

        results: Dict[str, HostState] = {}
        max_workers = min(len(live_hosts), self._cfg.post_scan_workers) if live_hosts else 1
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            for state in pool.map(_post_process, live_hosts):
                results[state.ip] = state

        logger.info(
            "Scan complete",
            extra={"live_hosts": len(results), "targets": targets},
        )
        return results

    # ------------------------------------------------------------------
    # Banner grabbing (non-HTTP open TCP ports)
    # ------------------------------------------------------------------

    def _grab_banners(self, host_ip: str, ports: Dict[str, PortInfo]) -> None:
        """
        Grab raw service banners for open TCP ports that aren't handled by
        the HTTP prober. Results are written directly into PortInfo.banner.

        If nmap already identified a version, the grabbed banner is stored
        alongside it — both are tracked independently for changes.
        If nmap found nothing, the raw banner becomes the sole fingerprint.
        """
        targets: List[Tuple[int, bool]] = []
        for port_key, info in ports.items():
            if info.state != "open":
                continue
            if not port_key.endswith("/tcp"):
                continue
            port_num = int(port_key.split("/")[0])
            if self._is_http_port(port_num, info.service):
                continue  # HTTP prober handles these
            use_tls = (
                port_num in _TLS_NONHTTP_PORTS
                or "ssl" in info.service.lower()
                or "tls" in info.service.lower()
            )
            targets.append((port_num, use_tls))

        if not targets:
            return

        grabbed = self._grabber.grab_all(host_ip, targets)
        for port_num_str, banner in grabbed.items():
            key = f"{port_num_str}/tcp"
            if key in ports and banner:
                ports[key].banner = banner
                logger.debug("Banner grabbed %s:%s → %r", host_ip, port_num_str, banner[:60])

    # ------------------------------------------------------------------
    # HTTP probing
    # ------------------------------------------------------------------

    def _probe_http(
        self, host_ip: str, ports: Dict[str, PortInfo]
    ) -> Dict[str, Dict[str, str]]:
        headers_map: Dict[str, Dict[str, str]] = {}

        for url, label in self._http_targets(host_ip, ports):
            captured = self._fetch_headers(url)
            if captured is None:
                # Try the other scheme if the first fails
                if url.startswith("https://"):
                    fallback = url.replace("https://", "http://")
                    fallback_label = label.replace("/https", "/http")
                    captured = self._fetch_headers(fallback)
                    if captured is not None:
                        headers_map[fallback_label] = captured
                continue
            headers_map[label] = captured

        return headers_map

    def _fetch_headers(self, url: str) -> Optional[Dict[str, str]]:
        try:
            resp = self._session.head(
                url,
                timeout=self._cfg.http_timeout,
                allow_redirects=self._cfg.http_follow_redirects,
            )
        except requests.exceptions.SSLError:
            try:
                resp = self._session.head(
                    url,
                    timeout=self._cfg.http_timeout,
                    allow_redirects=self._cfg.http_follow_redirects,
                    verify=False,
                )
            except Exception as exc:
                logger.debug("HTTP probe failed for %s: %s", url, exc)
                return None
        except Exception as exc:
            logger.debug("HTTP probe failed for %s: %s", url, exc)
            return None

        captured: Dict[str, str] = {"_status_code": str(resp.status_code)}
        for hdr in self._cfg.http_headers_of_interest:
            val = resp.headers.get(hdr)
            if val:
                captured[hdr] = val
        return captured

    def _http_targets(
        self, host_ip: str, ports: Dict[str, PortInfo]
    ) -> List[Tuple[str, str]]:
        """Return (url, label) pairs for each open port that looks HTTP-ish."""
        targets = []
        for port_key, info in ports.items():
            if info.state != "open":
                continue
            port_num = int(port_key.split("/")[0])
            svc = info.service.lower()

            if svc in _HTTPS_SERVICES or port_num in _HTTPS_PORTS:
                targets.append((f"https://{host_ip}:{port_num}/", f"{port_num}/https"))
            elif svc in _HTTP_SERVICES or port_num in _HTTP_PORTS:
                targets.append((f"http://{host_ip}:{port_num}/", f"{port_num}/http"))
            elif "ssl" in svc or "tls" in svc:
                targets.append((f"https://{host_ip}:{port_num}/", f"{port_num}/https"))

        return targets

    @staticmethod
    def _is_http_port(port_num: int, service: str) -> bool:
        svc = service.lower()
        return (
            svc in _HTTP_SERVICES
            or svc in _HTTPS_SERVICES
            or port_num in _HTTP_PORTS
            or port_num in _HTTPS_PORTS
            or "ssl" in svc
            or "tls" in svc
        )


def expand_targets_to_ips(targets: List[str]) -> List[str]:
    """
    Expand CIDRs to host IPs; resolve FQDNs to IPs.
    Returns a flat list used to detect hosts that go down between scans.

    Note: ipaddress.ip_network("x.x.x.x/32").hosts() is empty, so we
    special-case prefix-length 32/128 and yield the address itself.
    """
    all_ips: List[str] = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.prefixlen in (32, 128):
                all_ips.append(str(net.network_address))
            else:
                all_ips.extend(str(ip) for ip in net.hosts())
        except ValueError:
            try:
                all_ips.append(socket.gethostbyname(t))
            except socket.gaierror:
                all_ips.append(t)
    return all_ips
