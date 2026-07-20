"""A synthetic 60-person engineering firm.

Consistency is what makes a demo believable: the same hostnames, users, and IPs
must recur across syslog, NetFlow, and SNMP. Everything is derived from this
module so a story told on one feed lines up with the others.
"""
import random
from dataclasses import dataclass, field
from typing import List

from .config import cfg

SEED = 20260718
_rng = random.Random(SEED)


@dataclass
class Host:
    name: str
    ip: str
    role: str          # workstation | server | network | printer
    os: str
    critical: bool = False

    @property
    def fqdn(self) -> str:
        return f"{self.name}.{cfg.ORG_DOMAIN}"


@dataclass
class User:
    username: str
    display: str
    dept: str
    admin: bool = False
    workstation: str = ""

    @property
    def upn(self) -> str:
        return f"{self.username}@{cfg.ORG_DOMAIN}"


FIRST = ["kai", "leilani", "marcus", "aiko", "david", "noelani", "james", "mele",
         "robert", "keanu", "sarah", "hoku", "michael", "lani", "thomas",
         "anela", "brian", "kaleo", "jennifer", "makoa"]
LAST = ["chun", "santos", "kealoha", "tanaka", "medeiros", "wong", "silva",
        "kahale", "nakamura", "reyes", "lum", "pascual", "ka", "borges",
        "yamamoto", "cruz", "akana", "fernandez", "oshiro", "batalona"]
DEPTS = ["Engineering", "Design", "Field Ops", "Accounting", "Admin", "Projects"]

P = cfg.SITE_PREFIX


def _build_users() -> List[User]:
    users, seen = [], set()
    for i in range(58):
        f, l = _rng.choice(FIRST), _rng.choice(LAST)
        u = f"{f[0]}{l}"
        n = 2
        while u in seen:
            u, n = f"{f[0]}{l}{n}", n + 1
        seen.add(u)
        users.append(User(
            username=u,
            display=f"{f.capitalize()} {l.capitalize()}",
            dept=_rng.choice(DEPTS),
            admin=(i < 3),
            workstation=f"{P}-ws-{i+1:03d}",
        ))
    # A service account, because every demo needs one to be abused later.
    users.append(User(username="svc_backup", display="Backup Service",
                      dept="IT", admin=True, workstation=""))
    users.append(User(username="tames", display="Tim Ames", dept="IT",
                      admin=True, workstation=f"{P}-ws-001"))
    return users


def _build_hosts() -> List[Host]:
    hosts: List[Host] = []
    # Workstations 10.20.10.0/24
    for i in range(1, 59):
        hosts.append(Host(f"{P}-ws-{i:03d}", f"10.20.10.{i+10}", "workstation",
                          _rng.choice(["Windows 11 Pro"] * 8 + ["macOS 15"] * 2)))
    # Servers 10.20.20.0/24
    servers = [
        (f"{P}-dc-01", "10.20.20.10", "Windows Server 2022", True),
        (f"{P}-file-01", "10.20.20.11", "TrueNAS 24.10", True),
        (f"{P}-app-01", "10.20.20.12", "Windows Server 2022", True),
        (f"{P}-sql-01", "10.20.20.13", "Windows Server 2022", True),
        (f"{P}-print-01", "10.20.20.20", "Ubuntu 24.04", False),
        (f"{P}-vc-01", "10.20.20.30", "VMware ESXi 8", True),
    ]
    for n, ip, os_, crit in servers:
        hosts.append(Host(n, ip, "server", os_, crit))
    # Network gear 10.20.1.0/24
    net = [
        (f"{P}-fw-01", "10.20.1.1", "FortiOS 7.4", True),
        (f"{P}-sw-core", "10.20.1.2", "UniFi 8.0", True),
        (f"{P}-sw-a2", "10.20.1.3", "UniFi 8.0", False),
        (f"{P}-ap-lobby", "10.20.1.20", "UniFi 8.0", False),
        (f"{P}-ap-shop", "10.20.1.21", "UniFi 8.0", False),
        (f"gum-fw-01", "10.30.1.1", "FortiOS 7.4", True),   # Guam branch
    ]
    for n, ip, os_, crit in net:
        hosts.append(Host(n, ip, "network", os_, crit))
    hosts.append(Host(f"{P}-mfp-01", "10.20.30.50", "printer", "Ricoh"))
    return hosts


HOSTS: List[Host] = _build_hosts()
USERS: List[User] = _build_users()

WORKSTATIONS = [h for h in HOSTS if h.role == "workstation"]
SERVERS = [h for h in HOSTS if h.role == "server"]
NETWORK = [h for h in HOSTS if h.role == "network"]
FIREWALL = next(h for h in HOSTS if h.name.endswith("fw-01") and h.name.startswith(P))
DC = next(h for h in HOSTS if "-dc-" in h.name)
FILESERVER = next(h for h in HOSTS if "-file-" in h.name)

# Public destinations that look like ordinary business traffic.
BENIGN_EXTERNAL = [
    ("52.96.104.12", "outlook.office365.com", 443),
    ("13.107.42.14", "sharepoint.com", 443),
    ("142.250.217.78", "google.com", 443),
    ("104.18.32.47", "cloudflare.com", 443),
    ("23.45.112.9", "autodesk.com", 443),
    ("140.82.114.4", "github.com", 443),
    ("199.232.46.132", "ubuntu.com", 80),
]

# Reserved TEST-NET-3 (RFC 5737) - safe, routable-looking, never real.
HOSTILE_EXTERNAL = [
    ("203.0.113.66", "unknown", "Suspicious infrastructure"),
    ("203.0.113.104", "unknown", "Known scanner"),
    ("203.0.113.201", "unknown", "C2 candidate"),
]


MFP = next(h for h in HOSTS if "-mfp-" in h.name)


def cfg_domain() -> str:
    return cfg.ORG_DOMAIN


def cfg_prefix() -> str:
    return cfg.SITE_PREFIX


def rand_user(admin: bool = None) -> User:
    pool = USERS if admin is None else [u for u in USERS if u.admin == admin]
    return _rng.choice(pool)


def rand_workstation() -> Host:
    return _rng.choice(WORKSTATIONS)


def rand_external():
    return _rng.choice(BENIGN_EXTERNAL)
