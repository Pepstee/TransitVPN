"""CGNAT detection: router WAN-IP (UPnP IGD) vs public-IP comparison.

The reliable CGNAT signal is the *router's* WAN address as reported by the local
Internet Gateway Device over UPnP (``GetExternalIPAddress``). If that address is
itself non-routable (RFC 1918 / RFC 6598) — or differs from the public IP the
internet actually sees — there is a carrier NAT upstream of the router, i.e.
CGNAT. Comparing only a private local IP against the public IP cannot detect
this: a CGNAT'd host still sees the carrier's routable egress IP.
"""

from __future__ import annotations

import re
import socket
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin


class CgnatStatus(Enum):
    BEHIND_CGNAT = "behind_cgnat"
    NOT_BEHIND_CGNAT = "not_behind_cgnat"
    UNKNOWN = "unknown"


@dataclass
class CgnatResult:
    status: CgnatStatus
    public_ip: str | None = None
    local_ip: str | None = None
    router_external_ip: str | None = None
    upnp_available: bool = False
    details: list[str] = field(default_factory=list)

    @property
    def is_behind_cgnat(self) -> bool:
        return self.status == CgnatStatus.BEHIND_CGNAT


# RFC 6598 shared address space (CGNAT range): 100.64.0.0/10
_CGNAT_PREFIX = (100, 64)
_CGNAT_MASK = 0xFFC00000
_CGNAT_NETWORK = (100 << 24) | (64 << 16)

_PUBLIC_IP_URLS = [
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
    "https://ifconfig.me/ip",
]

_UPNP_MULTICAST = ("239.255.255.250", 1900)
_UPNP_DISCOVER = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "\r\n"
)


def _ip_str_to_int(ip: str) -> int:
    parts = [int(p) for p in ip.split(".")]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def _is_cgnat(ip: str) -> bool:
    """Return True if ip falls in 100.64.0.0/10 (RFC 6598)."""
    try:
        n = _ip_str_to_int(ip)
        return (n & _CGNAT_MASK) == _CGNAT_NETWORK
    except Exception:
        return False


def _is_private(ip: str) -> bool:
    """Return True if ip is RFC 1918 private or RFC 6598 CGNAT."""
    try:
        n = _ip_str_to_int(ip)
        return (
            (n >> 24) == 10  # 10.0.0.0/8
            or (n >> 20) == (172 << 4) | 1  # 172.16.0.0/12
            or (n >> 16) == (192 << 8) | 168  # 192.168.0.0/16
            or _is_cgnat(ip)
        )
    except Exception:
        return False


def _get_local_ip() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def _get_public_ip(timeout: float = 5.0) -> str | None:
    for url in _PUBLIC_IP_URLS:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
                return resp.read(64).decode().strip()
        except Exception:
            continue
    return None


def _probe_upnp(timeout: float = 2.0) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_UPNP_DISCOVER.encode(), _UPNP_MULTICAST)
        sock.recv(4096)
        sock.close()
        return True
    except Exception:
        return False


def _ssdp_location(timeout: float = 2.0) -> str | None:
    """Discover an IGD via SSDP M-SEARCH and return its description URL."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_UPNP_DISCOVER.encode(), _UPNP_MULTICAST)
        data = sock.recv(4096).decode("utf-8", "replace")
        sock.close()
    except Exception:
        return None
    for line in data.splitlines():
        if line.lower().startswith("location:"):
            return line.split(":", 1)[1].strip() or None
    return None


def _find_wan_service(description_xml: str, base_url: str) -> tuple[str, str] | None:
    """Return (control_url, service_type) for the WAN connection service."""
    for match in re.findall(r"<service>(.*?)</service>", description_xml, re.S):
        service_type = re.search(r"<serviceType>(.*?)</serviceType>", match, re.S)
        control_url = re.search(r"<controlURL>(.*?)</controlURL>", match, re.S)
        if not service_type or not control_url:
            continue
        stype = service_type.group(1).strip()
        if "WANIPConnection" in stype or "WANPPPConnection" in stype:
            return urljoin(base_url, control_url.group(1).strip()), stype
    return None


def _soap_external_ip(
    control_url: str, service_type: str, timeout: float = 2.0
) -> str | None:
    """Call GetExternalIPAddress on the IGD and return the router's WAN IP."""
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
        f'<u:GetExternalIPAddress xmlns:u="{service_type}"/>'
        "</s:Body></s:Envelope>"
    ).encode()
    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"{service_type}#GetExternalIPAddress"',
    }
    try:
        req = urllib.request.Request(
            control_url, data=body, headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            xml = resp.read().decode("utf-8", "replace")
    except Exception:
        return None
    match = re.search(r"<NewExternalIPAddress>(.*?)</NewExternalIPAddress>", xml, re.S)
    if not match:
        return None
    return match.group(1).strip() or None


def _get_router_external_ip(timeout: float = 2.0) -> str | None:
    """Retrieve the router's WAN IP from a UPnP IGD, or None if unavailable."""
    location = _ssdp_location(timeout=timeout)
    if not location:
        return None
    try:
        with urllib.request.urlopen(location, timeout=timeout) as resp:  # noqa: S310
            description = resp.read().decode("utf-8", "replace")
    except Exception:
        return None
    service = _find_wan_service(description, location)
    if not service:
        return None
    control_url, service_type = service
    return _soap_external_ip(control_url, service_type, timeout=timeout)


def detect_cgnat(*, dry_run: bool = False, timeout: float = 5.0) -> CgnatResult:
    """Detect whether this host is behind CGNAT.

    Args:
        dry_run: If True, skip all network calls and return UNKNOWN.
        timeout: Seconds to wait for network probes.

    Returns:
        CgnatResult with status and diagnostic detail.
    """
    if dry_run:
        return CgnatResult(
            status=CgnatStatus.UNKNOWN,
            details=["dry-run: network probes skipped"],
        )

    details: list[str] = []

    local_ip = _get_local_ip()
    if local_ip:
        details.append(f"local IP: {local_ip}")
    else:
        details.append("local IP: unavailable")

    public_ip = _get_public_ip(timeout=timeout)
    if public_ip:
        details.append(f"public IP: {public_ip}")
    else:
        details.append("public IP: unreachable")

    upnp = _probe_upnp(timeout=min(timeout, 2.0))
    if upnp:
        details.append("UPnP IGD responded")
    else:
        details.append("UPnP IGD: no response")

    router_ip = _get_router_external_ip(timeout=min(timeout, 2.0))
    if router_ip:
        details.append(f"router WAN IP (UPnP): {router_ip}")
    else:
        details.append("router WAN IP: unavailable")

    # Determine CGNAT status.
    #
    # The authoritative signal is the router's own WAN address (router_ip).
    # When present it decides the result: a private/CGNAT WAN address — or one
    # that differs from the IP the internet sees — means a carrier NAT sits
    # upstream of the router. We only fall back to the weaker local-vs-public
    # heuristic when the router will not report its WAN IP.
    if router_ip is not None:
        if _is_private(router_ip):
            status = CgnatStatus.BEHIND_CGNAT
            details.append("router WAN IP is non-routable → CGNAT upstream")
        elif public_ip is not None and router_ip != public_ip:
            status = CgnatStatus.BEHIND_CGNAT
            details.append("router WAN IP differs from public IP → CGNAT upstream")
        else:
            status = CgnatStatus.NOT_BEHIND_CGNAT
            details.append("router WAN IP is publicly routable → no CGNAT")
    elif public_ip is None:
        status = CgnatStatus.UNKNOWN
    elif local_ip and _is_private(local_ip) and not _is_cgnat(local_ip):
        # Local IP is RFC 1918; public IP differs — NAT is present but
        # need to check if public IP is itself in CGNAT range.
        if _is_cgnat(public_ip) or _is_private(public_ip):
            status = CgnatStatus.BEHIND_CGNAT
            details.append("public IP is non-routable → double-NAT / CGNAT")
        else:
            status = CgnatStatus.NOT_BEHIND_CGNAT
    elif local_ip and _is_cgnat(local_ip):
        status = CgnatStatus.BEHIND_CGNAT
        details.append("local IP is in CGNAT range (100.64.0.0/10)")
    elif public_ip == local_ip:
        status = CgnatStatus.NOT_BEHIND_CGNAT
        details.append("public IP matches local IP → no NAT")
    else:
        status = CgnatStatus.NOT_BEHIND_CGNAT

    return CgnatResult(
        status=status,
        public_ip=public_ip,
        local_ip=local_ip,
        router_external_ip=router_ip,
        upnp_available=upnp,
        details=details,
    )
