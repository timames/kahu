"""Reconnaissance API — DNS, IP discovery, and port scanning."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import platform
from typing import Any

import dns.resolver
import dns.reversename
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()
log = logging.getLogger(__name__)

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
TIMEOUT = 5.0
MAX_HOSTS = 256  # /24 max for IP scan
MAX_PORTS = 1024
PORT_TIMEOUT = 1.5
PING_CONCURRENCY = 50
PORT_CONCURRENCY = 100


class DnsLookupRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)
    record_types: list[str] = Field(default_factory=lambda: list(RECORD_TYPES))


class DnsRecord(BaseModel):
    type: str
    value: str
    ttl: int = 0
    priority: int | None = None


class DnsLookupResponse(BaseModel):
    domain: str
    records: list[DnsRecord]
    errors: dict[str, str] = {}


class ReverseLookupRequest(BaseModel):
    ip: str = Field(..., min_length=7, max_length=45)


class ReverseLookupResponse(BaseModel):
    ip: str
    hostnames: list[str]


@router.post("/dns", response_model=DnsLookupResponse)
async def dns_lookup(body: DnsLookupRequest) -> DnsLookupResponse:
    """Resolve DNS records for a domain (passive recon)."""
    domain = body.domain.strip().lower()
    if not _is_valid_domain(domain):
        raise HTTPException(400, "Invalid domain name")

    requested = [t.upper() for t in body.record_types if t.upper() in RECORD_TYPES]
    if not requested:
        requested = list(RECORD_TYPES)

    records: list[DnsRecord] = []
    errors: dict[str, str] = {}

    results = await asyncio.gather(
        *[_resolve(domain, rtype) for rtype in requested],
        return_exceptions=True,
    )

    for rtype, result in zip(requested, results, strict=False):
        if isinstance(result, Exception):
            errors[rtype] = str(result)
        else:
            records.extend(result)

    return DnsLookupResponse(domain=domain, records=records, errors=errors)


@router.post("/dns/reverse", response_model=ReverseLookupResponse)
async def reverse_lookup(body: ReverseLookupRequest) -> ReverseLookupResponse:
    """Reverse DNS lookup for an IP address."""
    ip = body.ip.strip()
    try:
        rev_name = dns.reversename.from_address(ip)
    except Exception:
        raise HTTPException(400, "Invalid IP address") from None

    hostnames: list[str] = []
    try:
        answers = await asyncio.to_thread(
            dns.resolver.resolve,
            rev_name,
            "PTR",
            lifetime=TIMEOUT,
        )
        hostnames = [str(rdata.target).rstrip(".") for rdata in answers]
    except dns.resolver.NXDOMAIN:
        pass
    except Exception as exc:
        log.debug("Reverse lookup failed for %s: %s", ip, exc)

    return ReverseLookupResponse(ip=ip, hostnames=hostnames)


async def _resolve(domain: str, rtype: str) -> list[DnsRecord]:
    """Resolve a single record type for a domain."""
    try:
        answers = await asyncio.to_thread(
            dns.resolver.resolve,
            domain,
            rtype,
            lifetime=TIMEOUT,
        )
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        raise ValueError(f"Domain {domain} does not exist") from None
    except dns.resolver.NoNameservers:
        raise ValueError("No nameservers available") from None
    except dns.exception.Timeout:
        raise ValueError("DNS query timed out") from None

    records: list[DnsRecord] = []
    ttl = int(answers.rrset.ttl) if answers.rrset else 0

    for rdata in answers:
        rec: dict[str, Any] = {"type": rtype, "ttl": ttl}
        if rtype == "MX":
            rec["value"] = str(rdata.exchange).rstrip(".")
            rec["priority"] = rdata.preference
        elif rtype == "SOA":
            rec["value"] = (
                f"{str(rdata.mname).rstrip('.')} "
                f"{str(rdata.rname).rstrip('.')} "
                f"serial={rdata.serial} "
                f"refresh={rdata.refresh} "
                f"retry={rdata.retry} "
                f"expire={rdata.expire} "
                f"minimum={rdata.minimum}"
            )
        else:
            rec["value"] = str(rdata).strip('"').rstrip(".")
        records.append(DnsRecord(**rec))

    return records


# ── IP Scanner ────────────────────────────────────────────


class IpScanRequest(BaseModel):
    target: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="IP, CIDR, or range (e.g. 192.168.1.0/24)",
    )
    timeout_ms: int = Field(default=1000, ge=100, le=5000)


class HostResult(BaseModel):
    ip: str
    alive: bool
    hostname: str = ""
    latency_ms: float | None = None


class IpScanResponse(BaseModel):
    target: str
    total_scanned: int
    alive_count: int
    hosts: list[HostResult]


@router.post("/ip-scan", response_model=IpScanResponse)
async def ip_scan(body: IpScanRequest) -> IpScanResponse:
    """Ping sweep to discover live hosts on a network."""
    try:
        hosts = _parse_targets(body.target)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e

    if len(hosts) > MAX_HOSTS:
        raise HTTPException(
            400, f"Too many hosts ({len(hosts)}). Max is {MAX_HOSTS} (use /24 or smaller)."
        )

    sem = asyncio.Semaphore(PING_CONCURRENCY)
    results = await asyncio.gather(*[_ping_host(str(h), body.timeout_ms, sem) for h in hosts])

    alive = [r for r in results if r.alive]
    # Sort: alive first, then by IP
    results.sort(key=lambda r: (not r.alive, ipaddress.ip_address(r.ip)))

    return IpScanResponse(
        target=body.target,
        total_scanned=len(results),
        alive_count=len(alive),
        hosts=results,
    )


async def _ping_host(ip: str, timeout_ms: int, sem: asyncio.Semaphore) -> HostResult:
    """Ping a single host and optionally resolve its hostname."""
    async with sem:
        is_win = platform.system().lower() == "windows"
        if is_win:
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            timeout_s = max(1, timeout_ms // 1000)
            cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_ms / 1000 + 2)
            alive = proc.returncode == 0
            latency = _parse_ping_latency(stdout.decode(errors="replace")) if alive else None
        except (TimeoutError, OSError):
            alive = False
            latency = None

        hostname = ""
        if alive:
            try:
                import socket

                hostname = await asyncio.to_thread(lambda: socket.getfqdn(ip))
                if hostname == ip:
                    hostname = ""
            except Exception:  # noqa: S110
                pass

        return HostResult(ip=ip, alive=alive, hostname=hostname, latency_ms=latency)


def _parse_ping_latency(output: str) -> float | None:
    """Extract average latency from ping output."""
    import re

    # Windows: Average = 1ms  |  Linux: min/avg/max = 0.5/1.0/1.5
    m = re.search(r"Average\s*=\s*(\d+)", output)
    if m:
        return float(m.group(1))
    m = re.search(r"=\s*[\d.]+/([\d.]+)/", output)
    if m:
        return float(m.group(1))
    return None


def _parse_targets(target: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse target string into a list of IP addresses."""
    target = target.strip()
    # CIDR notation
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR: {target}") from None
        return list(network.hosts()) or [network.network_address]

    # Range: 192.168.1.1-50
    if "-" in target and not target.startswith("-"):
        parts = target.split("-")
        if len(parts) == 2:
            try:
                base = ipaddress.ip_address(parts[0].strip())
                end_octet = int(parts[1].strip())
                base_octets = str(base).rsplit(".", 1)
                start_octet = int(base_octets[1])
                if end_octet < start_octet or end_octet > 255:
                    raise ValueError(f"Invalid range: {target}")
                return [
                    ipaddress.ip_address(f"{base_octets[0]}.{i}")
                    for i in range(start_octet, end_octet + 1)
                ]
            except (ValueError, IndexError):
                raise ValueError(f"Invalid range: {target}") from None

    # Single IP
    try:
        return [ipaddress.ip_address(target)]
    except ValueError:
        raise ValueError(
            f"Invalid target: {target}. Use an IP, CIDR "
            f"(e.g. 192.168.1.0/24), or range (e.g. 192.168.1.1-50)."
        ) from None


# ── Port Scanner ─────────────────────────────────────────


COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1521,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
    8888,
    9200,
    27017,
]

PORT_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


class PortScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=100)
    ports: str = Field(
        default="common",
        description="'common', 'all' (1-1024), or custom e.g. '22,80,443' or '1-100'",
    )
    timeout_ms: int = Field(default=1500, ge=100, le=10000)


class PortResult(BaseModel):
    port: int
    state: str  # "open" or "closed"
    service: str = ""


class PortScanResponse(BaseModel):
    target: str
    total_scanned: int
    open_count: int
    ports: list[PortResult]


@router.post("/port-scan", response_model=PortScanResponse)
async def port_scan(body: PortScanRequest) -> PortScanResponse:
    """TCP connect scan to discover open ports on a host."""
    target = body.target.strip()
    try:
        ipaddress.ip_address(target)
    except ValueError:
        # Allow hostnames too — resolve first
        import socket

        try:
            target = await asyncio.to_thread(socket.gethostbyname, target)
        except socket.gaierror:
            raise HTTPException(400, f"Cannot resolve hostname: {body.target}") from None

    ports = _parse_ports(body.ports)
    if len(ports) > MAX_PORTS:
        raise HTTPException(400, f"Too many ports ({len(ports)}). Max is {MAX_PORTS}.")

    sem = asyncio.Semaphore(PORT_CONCURRENCY)
    timeout_s = body.timeout_ms / 1000
    results = await asyncio.gather(*[_check_port(target, p, timeout_s, sem) for p in ports])

    open_ports = [r for r in results if r.state == "open"]
    # Show open ports first, then closed sorted by port number
    results.sort(key=lambda r: (r.state != "open", r.port))

    return PortScanResponse(
        target=target,
        total_scanned=len(results),
        open_count=len(open_ports),
        ports=results,
    )


async def _check_port(ip: str, port: int, timeout: float, sem: asyncio.Semaphore) -> PortResult:
    """Attempt a TCP connection to determine if a port is open."""
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return PortResult(port=port, state="open", service=PORT_NAMES.get(port, ""))
        except (TimeoutError, OSError, ConnectionRefusedError):
            return PortResult(port=port, state="closed", service=PORT_NAMES.get(port, ""))


def _parse_ports(spec: str) -> list[int]:
    """Parse port specification into a list of port numbers."""
    spec = spec.strip().lower()
    if spec == "common":
        return COMMON_PORTS
    if spec == "all":
        return list(range(1, 1025))

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            s, e = int(start), int(end)
            if s < 1 or e > 65535 or s > e:
                raise HTTPException(400, f"Invalid port range: {part}")
            ports.update(range(s, e + 1))
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise HTTPException(400, f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def _is_valid_domain(domain: str) -> bool:
    """Basic domain name validation."""
    if not domain or len(domain) > 253:
        return False
    # Strip trailing dot
    if domain.endswith("."):
        domain = domain[:-1]
    parts = domain.split(".")
    if len(parts) < 2:
        return False
    import re

    label_re = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
    return all(label_re.match(p) for p in parts)
