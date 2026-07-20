"""Wire-protocol emitters: syslog, NetFlow v5, SNMP traps.

Each emitter is deliberately dumb - it puts bytes on the wire. All storytelling
lives in scenarios.py. Every send is wrapped so a dead collector degrades the
demo rather than crashing it.
"""
import logging
import socket
import struct
import threading
import time
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from .config import cfg

log = logging.getLogger("emitters")

# Lazy import to avoid circular dependency
_webhook = None

def _get_webhook():
    global _webhook
    if _webhook is None:
        from . import webhook as wh
        _webhook = wh
    return _webhook

_BOOT = time.time()
_lock = threading.Lock()
_counters = {"syslog": 0, "netflow": 0, "snmp": 0, "errors": 0}


def counters() -> dict:
    with _lock:
        return dict(_counters)


def _bump(key: str, n: int = 1) -> None:
    with _lock:
        _counters[key] = _counters.get(key, 0) + n


def _ip2int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


# ----------------------------------------------------------------------------
# Syslog
# ----------------------------------------------------------------------------
FAC = {"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
       "authpriv": 10, "local0": 16, "local1": 17, "local4": 20, "local7": 23}
SEV = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warning": 4,
       "notice": 5, "info": 6, "debug": 7}


class SyslogEmitter:
    def __init__(self) -> None:
        self.host = cfg.TARGET_HOST
        self.port = cfg.SYSLOG_PORT
        self.proto = cfg.SYSLOG_PROTO
        self._tcp: Optional[socket.socket] = None
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _tcp_sock(self) -> socket.socket:
        if self._tcp is None:
            s = socket.create_connection((self.host, self.port), timeout=5)
            self._tcp = s
        return self._tcp

    def send(self, host: str, tag: str, message: str,
             facility: str = "local0", severity: str = "info") -> None:
        pri = FAC.get(facility, 16) * 8 + SEV.get(severity, 6)
        now = datetime.now(timezone.utc)

        if cfg.SYSLOG_FORMAT == "rfc5424":
            ts = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            line = f"<{pri}>1 {ts} {host} {tag} - - - {message}"
        else:
            ts = now.strftime("%b %d %H:%M:%S")
            if ts[4] == "0":  # RFC3164 wants a space-padded day
                ts = ts[:4] + " " + ts[5:]
            line = f"<{pri}>{ts} {host} {tag}: {message}"

        # Also queue for Kuahene webhook delivery
        try:
            _get_webhook().queue_alert(host, tag, message, facility, severity)
        except Exception:
            pass

        if cfg.DRY_RUN:
            print(f"[syslog] {line}")
            _bump("syslog")
            return

        try:
            data = (line + "\n").encode("utf-8", "replace")
            if self.proto == "tcp":
                self._tcp_sock().sendall(data)
            else:
                self._udp.sendto(data[:-1], (self.host, self.port))
            _bump("syslog")
        except Exception as exc:  # noqa: BLE001 - demo must not die
            self._tcp = None
            _bump("errors")
            log.warning("syslog send failed: %s", exc)


# ----------------------------------------------------------------------------
# NetFlow v5
# ----------------------------------------------------------------------------
class NetFlowEmitter:
    """NetFlow v5: 24-byte header + N x 48-byte records, max 30 per packet."""

    def __init__(self) -> None:
        self.host = cfg.TARGET_HOST
        self.port = cfg.NETFLOW_PORT
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._seq = 0

    def _header(self, count: int) -> bytes:
        now = time.time()
        uptime_ms = int((now - _BOOT) * 1000) & 0xFFFFFFFF
        return struct.pack(
            "!HHIIIIBBH",
            5, count, uptime_ms, int(now), int((now % 1) * 1e9),
            self._seq, 0, 0, 0,
        )

    @staticmethod
    def _record(src: str, dst: str, sport: int, dport: int, proto: int,
                packets: int, octets: int, tcp_flags: int = 0x1B) -> bytes:
        now_ms = int((time.time() - _BOOT) * 1000) & 0xFFFFFFFF
        first = max(0, now_ms - 2000)
        return struct.pack(
            "!IIIHHIIIIHHBBBBHHBBH",
            _ip2int(src), _ip2int(dst), 0,          # src, dst, nexthop
            0, 0,                                    # input/output ifIndex
            packets, octets,
            first, now_ms,
            sport, dport,
            0, tcp_flags, proto, 0,                  # pad, flags, proto, tos
            0, 0,                                    # src_as, dst_as
            24, 24, 0,                               # masks, pad
        )

    def send(self, flows: List[Tuple]) -> None:
        """flows: list of (src, dst, sport, dport, proto, packets, octets)."""
        if not flows:
            return
        for i in range(0, len(flows), 30):
            chunk = flows[i:i + 30]
            body = b"".join(self._record(*f) for f in chunk)
            pkt = self._header(len(chunk)) + body
            self._seq += len(chunk)

            if cfg.DRY_RUN:
                print(f"[netflow] {len(chunk)} flows ({len(pkt)} bytes)")
                _bump("netflow", len(chunk))
                continue
            try:
                self._sock.sendto(pkt, (self.host, self.port))
                _bump("netflow", len(chunk))
            except Exception as exc:  # noqa: BLE001
                _bump("errors")
                log.warning("netflow send failed: %s", exc)


# ----------------------------------------------------------------------------
# SNMP traps (v2c)
# ----------------------------------------------------------------------------
class SNMPEmitter:
    """Sends v2c traps via pysnmp. Degrades to a log line if pysnmp is absent."""

    def __init__(self) -> None:
        self.host = cfg.TARGET_HOST
        self.port = cfg.SNMP_TRAP_PORT
        self.community = cfg.SNMP_COMMUNITY
        self._ok = False
        try:
            from pysnmp.hlapi import (  # noqa: F401
                CommunityData, ContextData, NotificationType, ObjectIdentity,
                SnmpEngine, UdpTransportTarget, sendNotification,
            )
            self._ok = True
        except Exception as exc:  # noqa: BLE001
            log.warning("pysnmp unavailable (%s); SNMP traps will be logged only", exc)

    def send(self, trap_oid: str, source: str, varbinds=None) -> None:
        varbinds = varbinds or []
        if cfg.DRY_RUN or not self._ok:
            print(f"[snmp] trap {trap_oid} from {source} vb={varbinds}")
            _bump("snmp")
            return
        try:
            from pysnmp.hlapi import (
                CommunityData, ContextData, NotificationType, ObjectIdentity,
                ObjectType, OctetString, SnmpEngine, UdpTransportTarget,
                sendNotification,
            )
            nt = NotificationType(ObjectIdentity(trap_oid))
            for oid, val in varbinds:
                nt = nt.addVarBinds(
                    ObjectType(ObjectIdentity(oid), OctetString(str(val)))
                )
            errind, errstat, _, _ = next(
                sendNotification(
                    SnmpEngine(),
                    CommunityData(self.community, mpModel=1),
                    UdpTransportTarget((self.host, self.port), timeout=2, retries=0),
                    ContextData(),
                    "trap",
                    nt,
                )
            )
            if errind or errstat:
                _bump("errors")
                log.warning("snmp trap error: %s %s", errind, errstat)
            else:
                _bump("snmp")
        except Exception as exc:  # noqa: BLE001
            _bump("errors")
            log.warning("snmp send failed: %s", exc)


syslog = SyslogEmitter()
netflow = NetFlowEmitter()
snmp = SNMPEmitter()
