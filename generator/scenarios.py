"""Baseline noise and triggerable demo scenarios.

Every scenario here *narrates* activity as log records. Nothing in this file
touches, scans, or authenticates against any real system - it composes syslog
lines, NetFlow records, and SNMP traps that describe a story. That is what a
detection demo needs, and it keeps the generator safe to run anywhere.

Each scenario is a generator function yielding (delay_seconds, callable).
The engine walks it, so scenarios play out over realistic time rather than
dumping 400 events in one tick.
"""
import random
from datetime import datetime
from typing import Callable, Dict, Iterator, List, Tuple

from . import topology as T
from .emitters import netflow, snmp, syslog

rng = random.Random()

Step = Tuple[float, Callable[[], None]]

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

WIN_LOGON_OK = "4624"
WIN_LOGON_FAIL = "4625"
WIN_PRIV_ASSIGNED = "4672"
WIN_GROUP_ADD = "4728"
WIN_ACCT_CREATED = "4720"
WIN_LOG_CLEARED = "1102"
WIN_SVC_INSTALLED = "7045"


def win_event(host: str, event_id: str, user: str, msg: str,
              severity: str = "info") -> None:
    syslog.send(host, "WinEventLog",
                f"EventID={event_id} User={user} Computer={host} {msg}",
                facility="local0", severity=severity)


def fw_event(action: str, src: str, dst: str, dport: int, msg: str,
             severity: str = "notice") -> None:
    syslog.send(T.FIREWALL.name, "fortigate",
                f'action="{action}" srcip={src} dstip={dst} dstport={dport} {msg}',
                facility="local4", severity=severity)


def flow(src: str, dst: str, sport: int, dport: int, proto: int,
         pkts: int, octets: int) -> None:
    netflow.send([(src, dst, sport, dport, proto, pkts, octets)])


def bulk_flows(rows: List[Tuple]) -> None:
    netflow.send(rows)


# ---------------------------------------------------------------------------
# BASELINE - the ambient hum of a working office
# ---------------------------------------------------------------------------

def business_hours_factor(tz_now: datetime) -> float:
    """Diurnal curve: dead overnight, ramp 6am, peak 9-11 and 13-16, taper 5pm."""
    h = tz_now.hour + tz_now.minute / 60.0
    dow = tz_now.weekday()
    if dow >= 5:                       # weekend
        return 0.12
    if h < 5.5 or h > 19:
        return 0.08
    if h < 7:
        return 0.25
    if h < 9:
        return 0.7
    if h < 11.5:
        return 1.0
    if h < 13:
        return 0.6                     # lunch
    if h < 16.5:
        return 0.95
    if h < 18:
        return 0.5
    return 0.2


def baseline_tick() -> None:
    """One tick of ordinary activity. Called ~ once per second by the engine."""
    r = rng.random()

    if r < 0.30:
        u, ws = T.rand_user(), T.rand_workstation()
        win_event(ws.name, WIN_LOGON_OK, u.upn, "LogonType=2 Status=Success")
    elif r < 0.38:
        u, ws = T.rand_user(), T.rand_workstation()
        win_event(ws.name, WIN_LOGON_FAIL, u.upn,
                  "LogonType=2 Status=0xC000006A Reason=BadPassword",
                  severity="warning")
    elif r < 0.55:
        ws = T.rand_workstation()
        ip, name, port = T.rand_external()
        fw_event("accept", ws.ip, ip, port, f'service="HTTPS" hostname="{name}"')
        flow(ws.ip, ip, rng.randint(49152, 65535), port, 6,
             rng.randint(8, 120), rng.randint(1200, 90000))
    elif r < 0.68:
        ws = T.rand_workstation()
        flow(ws.ip, T.FILESERVER.ip, rng.randint(49152, 65535), 445, 6,
             rng.randint(20, 400), rng.randint(4000, 900000))
    elif r < 0.76:
        ws = T.rand_workstation()
        flow(ws.ip, T.DC.ip, rng.randint(49152, 65535), 389, 6, 4, 620)
    elif r < 0.82:
        syslog.send(T.FILESERVER.name, "smbd",
                    f"session opened for user {T.rand_user().username} "
                    f"from {T.rand_workstation().ip}")
    elif r < 0.87:
        h = rng.choice(T.NETWORK)
        syslog.send(h.name, "unifi",
                    f'event="EVT_AP_Connected" client={_mac()} ssid="KaiPacific-Corp"')
    elif r < 0.91:
        syslog.send(T.MFP.name, "printer",
                    f"job completed user={T.rand_user().username} pages={rng.randint(1,40)}")
    elif r < 0.95:
        ws = T.rand_workstation()
        syslog.send(ws.name, "Defender",
                    f"ScanCompleted user={T.rand_user().upn} threats=0")
    else:
        h = rng.choice(T.NETWORK)
        snmp.send("1.3.6.1.6.3.1.1.5.3", h.name,
                  [("1.3.6.1.2.1.2.2.1.2", f"port{rng.randint(1,24)}")])


def _mac() -> str:
    return ":".join(f"{rng.randint(0,255):02x}" for _ in range(6))


# ---------------------------------------------------------------------------
# SCENARIOS
# ---------------------------------------------------------------------------

def s_brute_force() -> Iterator[Step]:
    """Password spray against the VPN/portal from a hostile address."""
    attacker = T.HOSTILE_EXTERNAL[1][0]
    victims = [T.rand_user() for _ in range(12)]
    yield 0, lambda: syslog.send(
        T.FIREWALL.name, "fortigate",
        f'action="ssl-login-fail" srcip={attacker} user="administrator" '
        f'reason="invalid credentials"', facility="local4", severity="warning")
    for i, u in enumerate(victims):
        for attempt in range(rng.randint(3, 6)):
            def mk(user=u):
                syslog.send(T.FIREWALL.name, "fortigate",
                            f'action="ssl-login-fail" srcip={attacker} '
                            f'user="{user.username}" reason="invalid credentials"',
                            facility="local4", severity="warning")
                win_event(T.DC.name, WIN_LOGON_FAIL, user.upn,
                          f"LogonType=3 Status=0xC000006A Source={attacker}",
                          severity="warning")
            yield rng.uniform(0.3, 1.4), mk
    # One succeeds. This is the moment the room goes quiet.
    winner = victims[7]
    yield 2.0, lambda: syslog.send(
        T.FIREWALL.name, "fortigate",
        f'action="ssl-login-success" srcip={attacker} user="{winner.username}" '
        f'tunnel="SSLVPN"', facility="local4", severity="alert")
    yield 1.0, lambda: win_event(
        T.DC.name, WIN_LOGON_OK, winner.upn,
        f"LogonType=10 Status=Success Source={attacker}", severity="alert")


def s_lateral_movement() -> Iterator[Step]:
    """Compromised workstation enumerates and pivots toward the DC."""
    ws = T.rand_workstation()
    yield 0, lambda: win_event(ws.name, WIN_SVC_INSTALLED, "SYSTEM",
                               'ServiceName="PSEXESVC" ImagePath="%SystemRoot%\\PSEXESVC.exe"',
                               severity="warning")
    targets = rng.sample(T.WORKSTATIONS, 14)
    yield 1.0, lambda: bulk_flows(
        [(ws.ip, t.ip, rng.randint(49152, 65535), 445, 6, 3, 180) for t in targets])
    for t in targets[:8]:
        yield rng.uniform(0.2, 0.8), (lambda tgt=t: win_event(
            tgt.name, WIN_LOGON_FAIL, "svc_backup@" + T.cfg_domain(),
            f"LogonType=3 Status=0xC000006D Source={ws.ip}", severity="warning"))
    yield 1.5, lambda: win_event(
        T.DC.name, WIN_LOGON_OK, "svc_backup@" + T.cfg_domain(),
        f"LogonType=3 Status=Success Source={ws.ip}", severity="alert")
    yield 1.0, lambda: win_event(
        T.DC.name, WIN_PRIV_ASSIGNED, "svc_backup@" + T.cfg_domain(),
        "Privileges=SeDebugPrivilege,SeTcbPrivilege", severity="alert")


def s_privilege_escalation() -> Iterator[Step]:
    """A standard account is quietly added to Domain Admins."""
    u = T.rand_user(admin=False)
    actor = "svc_backup@" + T.cfg_domain()
    yield 0, lambda: win_event(T.DC.name, WIN_ACCT_CREATED, actor,
                               'TargetAccount="sqlmaint" Description="SQL Maintenance"',
                               severity="warning")
    yield 2.0, lambda: win_event(T.DC.name, WIN_GROUP_ADD, actor,
                                 'Group="Domain Admins" Member="sqlmaint"',
                                 severity="alert")
    yield 1.5, lambda: win_event(T.DC.name, WIN_GROUP_ADD, actor,
                                 f'Group="Enterprise Admins" Member="{u.username}"',
                                 severity="alert")
    yield 3.0, lambda: win_event(T.DC.name, WIN_LOG_CLEARED, actor,
                                 "The audit log was cleared", severity="crit")


def s_c2_beacon() -> Iterator[Step]:
    """Textbook beaconing: small, regular, long-lived, to nowhere good."""
    ws = T.rand_workstation()
    c2 = T.HOSTILE_EXTERNAL[2][0]
    yield 0, lambda: syslog.send(ws.name, "Defender",
                                 f'Behavior:Win32/Suspicious.Beacon detected '
                                 f'process="updatesvc.exe" user={T.rand_user().upn}',
                                 severity="warning")
    for i in range(24):
        yield 2.5, (lambda: (
            flow(ws.ip, c2, rng.randint(49152, 65535), 443, 6, 6, rng.randint(480, 620)),
            fw_event("accept", ws.ip, c2, 443,
                     'service="HTTPS" app="unknown" duration=2', severity="warning"),
        ))


def s_data_exfiltration() -> Iterator[Step]:
    """Large after-hours pull from the file server, then out the door."""
    ws = T.rand_workstation()
    u = T.rand_user()
    dest = T.HOSTILE_EXTERNAL[0][0]
    yield 0, lambda: syslog.send(
        T.FILESERVER.name, "smbd",
        f'session opened for user {u.username} from {ws.ip} share="Projects"')
    yield 1.0, lambda: bulk_flows(
        [(T.FILESERVER.ip, ws.ip, 445, rng.randint(49152, 65535), 6,
          rng.randint(4000, 9000), rng.randint(40_000_000, 90_000_000))
         for _ in range(12)])
    yield 2.0, lambda: syslog.send(
        T.FILESERVER.name, "audit",
        f'user={u.username} action="bulk_read" files=2841 bytes=734003200 '
        f'share="Projects" src={ws.ip}', severity="warning")
    yield 2.0, lambda: bulk_flows(
        [(ws.ip, dest, rng.randint(49152, 65535), 443, 6,
          rng.randint(3000, 8000), rng.randint(30_000_000, 70_000_000))
         for _ in range(10)])
    yield 1.0, lambda: fw_event(
        "accept", ws.ip, dest, 443,
        'service="HTTPS" app="Unknown-Upload" sentbyte=612000000',
        severity="alert")


def s_ransomware() -> Iterator[Step]:
    """Shadow copies deleted, then mass file rename. The one that ends careers."""
    ws = T.rand_workstation()
    u = T.rand_user()
    yield 0, lambda: win_event(ws.name, "4688", u.upn,
                               'Process="vssadmin.exe" CommandLine="delete shadows /all /quiet"',
                               severity="crit")
    yield 1.0, lambda: win_event(ws.name, "4688", u.upn,
                                 'Process="wbadmin.exe" CommandLine="delete catalog -quiet"',
                                 severity="crit")
    yield 1.5, lambda: syslog.send(ws.name, "Defender",
                                   "Ransom:Win32/Generic.A blocked=false action=quarantine_failed",
                                   severity="emerg")
    for i in range(10):
        yield 0.6, lambda: syslog.send(
            T.FILESERVER.name, "audit",
            f'user={u.username} action="rename" count={rng.randint(400,900)} '
            f'ext_to=".locked" share="Projects" src={ws.ip}', severity="crit")
    yield 1.0, lambda: snmp.send("1.3.6.1.4.1.9.9.43.2.0.1", T.FILESERVER.name,
                                 [("1.3.6.1.2.1.1.5", "STORAGE-CRITICAL")])


def s_device_failure() -> Iterator[Step]:
    """Not an attack - an infrastructure problem. Shows non-security value."""
    sw = T.NETWORK[1]
    yield 0, lambda: snmp.send("1.3.6.1.6.3.1.1.5.3", sw.name,
                               [("1.3.6.1.2.1.2.2.1.2", "port14"),
                                ("1.3.6.1.2.1.2.2.1.8", "down")])
    yield 1.0, lambda: syslog.send(sw.name, "unifi",
                                   'event="EVT_SW_PortError" port=14 errors=8241 crc=true',
                                   severity="err")
    yield 2.0, lambda: snmp.send("1.3.6.1.4.1.4413.1.1.1", sw.name,
                                 [("temperature", "78"), ("threshold", "70")])
    yield 1.0, lambda: syslog.send(sw.name, "unifi",
                                   'event="EVT_SW_HighTemp" temp=78C threshold=70C',
                                   severity="crit")
    yield 2.0, lambda: syslog.send(T.FIREWALL.name, "fortigate",
                                   'action="ha-failover" reason="link-monitor-fail" '
                                   'unit="secondary"', severity="alert")


def s_impossible_travel() -> Iterator[Step]:
    """VPN sessions from two continents, minutes apart, one account."""
    u = T.rand_user()
    yield 0, lambda: syslog.send(
        T.FIREWALL.name, "fortigate",
        f'action="ssl-login-success" user="{u.username}" srcip=203.0.113.14 '
        f'geo="US/Hawaii" tunnel="SSLVPN"', facility="local4")
    yield 4.0, lambda: syslog.send(
        T.FIREWALL.name, "fortigate",
        f'action="ssl-login-success" user="{u.username}" srcip=203.0.113.222 '
        f'geo="RU/Moscow" tunnel="SSLVPN"', facility="local4", severity="alert")
    yield 1.0, lambda: win_event(
        T.DC.name, WIN_LOGON_OK, u.upn,
        "LogonType=10 Status=Success Source=203.0.113.222", severity="alert")


def s_port_scan() -> Iterator[Step]:
    """External reconnaissance sweep - cheap, fast, always demos well."""
    src = T.HOSTILE_EXTERNAL[1][0]
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
             1433, 3306, 3389, 5432, 5900, 8080, 8443]
    for chunk_start in range(0, len(ports), 5):
        chunk = ports[chunk_start:chunk_start + 5]
        yield 0.5, (lambda c=chunk: bulk_flows(
            [(src, T.FIREWALL.ip, rng.randint(1024, 65535), p, 6, 1, 44) for p in c]))
        yield 0.3, (lambda c=chunk: [
            fw_event("deny", src, T.FIREWALL.ip, p, 'service="scan" policy="deny-all"',
                     severity="warning") for p in c])


SCENARIOS: Dict[str, dict] = {
    "brute_force": {
        "fn": s_brute_force,
        "title": "VPN password spray",
        "desc": "Hundreds of failed logins from one hostile IP across many accounts - then one succeeds.",
        "duration": "~45s",
    },
    "port_scan": {
        "fn": s_port_scan,
        "title": "External port scan",
        "desc": "Reconnaissance sweep against the firewall. Fast, obvious, good opener.",
        "duration": "~10s",
    },
    "impossible_travel": {
        "fn": s_impossible_travel,
        "title": "Impossible travel",
        "desc": "One account logs in from Honolulu and Moscow five minutes apart.",
        "duration": "~10s",
    },
    "lateral_movement": {
        "fn": s_lateral_movement,
        "title": "Lateral movement",
        "desc": "PsExec service install, SMB sweep across workstations, then a service account hits the DC.",
        "duration": "~20s",
    },
    "privilege_escalation": {
        "fn": s_privilege_escalation,
        "title": "Privilege escalation + log wipe",
        "desc": "New account created, added to Domain Admins, audit log cleared.",
        "duration": "~15s",
    },
    "c2_beacon": {
        "fn": s_c2_beacon,
        "title": "C2 beaconing",
        "desc": "Regular small-payload callbacks every 2.5s to unknown infrastructure.",
        "duration": "~60s",
    },
    "data_exfiltration": {
        "fn": s_data_exfiltration,
        "title": "Data exfiltration",
        "desc": "Bulk read from the Projects share, then 600MB out to an external host.",
        "duration": "~25s",
    },
    "ransomware": {
        "fn": s_ransomware,
        "title": "Ransomware detonation",
        "desc": "Shadow copies deleted, AV quarantine fails, mass .locked renames on the file server.",
        "duration": "~20s",
    },
    "device_failure": {
        "fn": s_device_failure,
        "title": "Infrastructure fault (SNMP)",
        "desc": "Switch port errors, thermal alarm, firewall HA failover. Not every alert is an attacker.",
        "duration": "~15s",
    },
}
