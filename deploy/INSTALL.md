# Installing Kahu

Three installers, all targeting Ubuntu 22.04 / 24.04:

| Script | What it builds |
|---|---|
| `deploy/install.sh` | The appliance — one box, or three-plus by role |
| `deploy/install-probe.sh` | A remote-site syslog collector VM |
| `scripts/install-agent.ps1` | Windows endpoint agent (pre-existing) |

---

## 1. All-in-one

The whole stack on one machine. This is the normal deployment.

```bash
git clone https://github.com/timames/kahu.git /opt/kahu
cd /opt/kahu
sudo ./deploy/install.sh
```

It will install Docker, tune the kernel, generate secrets and certificates, pick
a GPU or CPU configuration, start everything, and pull the Ollama model.

Sizing: 16 GB RAM is the floor, 32 GB+ comfortable, and the installer sizes the
Wazuh indexer JVM heap at a quarter of host RAM (capped at 31 GB, the point where
the JVM loses compressed object pointers). A 128 GB box gets a 31 GB heap.

Non-interactive:

```bash
sudo ./deploy/install.sh --yes --gpu off --model mistral:7b-instruct-v0.3-q4_K_M
```

### GPU

GPU is opt-in and auto-detected. `--gpu auto` (the default) adds the NVIDIA
device reservation and installs the container toolkit only when `nvidia-smi`
reports a card; otherwise Ollama runs on CPU. Force either way with
`--gpu force` / `--gpu off`.

This matters because an unconditional NVIDIA reservation makes `docker compose
up` fail outright on a host without a card — which is why the reservation lives
in `deploy/compose/ollama-gpu.yml` rather than in `docker-compose.yml`.

---

## 2. Three or more machines

Split by **resource**, not by network zone:

| Role | Services | Wants |
|---|---|---|
| `core` | Kahu API, Postgres, Redis | Modest CPU, fast disk |
| `siem` | Wazuh manager, indexer, dashboard | RAM (JVM heap + indices) |
| `ai` | Ollama | GPU, or many CPU cores |
| `scanner` | Greenbone / OpenVAS | CPU and disk; feed sync runs for hours |

With three machines, run `core`, `siem` and `ai`; Greenbone stays on `core`
unless you give it a fourth box.

**Install `core` first** — it generates the shared secrets and certificates and
emits a join bundle for the others.

```bash
# 1. core node
sudo ./deploy/install.sh --mode distributed --role core \
     --siem-host siem.lan --ai-host gpu.lan
# writes kahu-join-bundle.tar.gz

# 2. copy the bundle to each other node, then on each:
sudo ./deploy/install.sh --mode distributed --role siem \
     --core-host core.lan --join kahu-join-bundle.tar.gz
sudo ./deploy/install.sh --mode distributed --role ai \
     --core-host core.lan --join kahu-join-bundle.tar.gz
```

The join bundle contains `.env` and the Wazuh certificates. It is secret —
copy it over `scp`, and delete it from the target once installed.

### Ports between nodes

| From | To | Port |
|---|---|---|
| core | siem | 55000/tcp (Wazuh API), 9200/tcp (indexer) |
| core | ai | 11434/tcp (Ollama) |
| core | scanner | 9392/tcp (Greenbone) |
| agents, probes | siem | 1514/tcp, 1515/tcp, 514/udp+tcp |

Postgres and Redis are never published; only the `core` node talks to them.

**Ollama has no authentication.** Anything that reaches 11434 can use the model.
Restrict that port to the core node at the firewall — the installer does not do
this for you.

### Why standalone compose files, not overlays

`deploy/compose/role-*.yml` are complete files rather than overlays of
`docker-compose.yml`. Compose *merges* `depends_on` rather than removing
entries, so overlaying the all-in-one file would still drag Postgres, Redis and
Ollama onto every box.

### One thing that does not scale out

`core` itself is single-instance. The auto-disposition tolerance, the Arsenal
unlock flag and the dedup window all live in process memory
(`auto_disposition._current_tolerance`, `arsenal/mode.py._unlocked`,
`filters.DeduplicationWindow`). Two `core` nodes would disagree about all three.
Distribute the supporting services freely; do not run a second `core`.

---

## 3. Remote-site probe

A small VM at a site with no appliance. It accepts syslog from local network gear
that cannot run an agent — firewalls, switches, APs, printers, hypervisors —
spools to disk across WAN outages, and ships everything to the Wazuh manager over
the encrypted agent channel rather than firing plaintext syslog across the WAN.

```bash
sudo ./deploy/install-probe.sh --manager siem.example.com --site branch-01
```

2 vCPU / 2 GB RAM is plenty. No Docker; rsyslog and the Wazuh agent are packages.

Then point each device's syslog at the probe on port 514.

### Cloud and virtual

`deploy/probe-cloud-init.yaml` is a cloud-init file — edit the three values at
the top and paste it into:

- **Azure** — VM creation → Advanced → Custom data
- **AWS** — EC2 launch → Advanced details → User data
- **VMware** — vApp properties, or `guestinfo.userdata` base64-encoded
- **Proxmox** — `qm set <vmid> --cicustom "user=local:snippets/probe-cloud-init.yaml"`

Cloud VMs need 514/udp opened in the Azure NSG or AWS security group as well as
in `ufw`; the installer only does `ufw`.

By default the probe accepts syslog only from its own subnet. Override with
`--allow-cidr`. Do not widen this to `0.0.0.0/0` on an internet-facing VM — an
open 514 is a log-injection path straight into the SIEM.

Verify:

```bash
/var/ossec/bin/wazuh-control status
ls -la /var/log/kahu-probe/            # one file per source device
logger -n 127.0.0.1 -P 514 -d "kahu probe test"
```

---

## Secrets

`install.sh` generates `SECRET_KEY`, `POSTGRES_PASSWORD`, `WAZUH_API_PASSWORD`
and `GREENBONE_PASSWORD` into `.env` (mode 0600) and **preserves them on re-run**
— running the installer again will not rotate your keys or orphan your database.
Back `.env` up. Losing `SECRET_KEY` invalidates every issued JWT.

### The indexer password is not generated

`WAZUH_INDEXER_PASSWORD` defaults to `admin` and the installer deliberately does
not randomise it. The indexer's credential is a bcrypt hash baked into the
image's `internal_users.yml`; that variable only changes what the manager and
dashboard *send*. Setting it to a random value would leave them authenticating
with a password the indexer has never seen, and the Wazuh stack would come up
unhealthy.

To change it properly: generate a hash with the image's
`plugins/opensearch-security/tools/hash.sh`, mount a modified
`internal_users.yml` into `wazuh-indexer`, re-run `securityadmin.sh`, then set
`WAZUH_INDEXER_PASSWORD` to match.

Until then, **keep 9200 off untrusted networks.**

### TLS between nodes is not verified

`clients/wazuh.py` uses `httpx.AsyncClient(verify=False)` throughout, and the
manager runs with `FILEBEAT_SSL_VERIFICATION_MODE: none`. Traffic is encrypted
but the certificate is not checked, so a distributed install assumes a trusted
network path between nodes. The installer still issues certificates with correct
SANs (`KAHU_EXTRA_SAN` in `config/wazuh/generate-certs.sh`) so that verification
can be switched on later without reissuing anything.

---

## Re-running and rollback

All three installers are idempotent: existing secrets, certificates and agent
enrolments are detected and left alone, and `.env` is backed up before rewrite.

```bash
cd /opt/kahu
docker compose --env-file .env logs -f core     # all-in-one
docker compose --env-file .env down             # stop, keep volumes
docker compose --env-file .env down -v          # stop and DESTROY data
```

Greenbone's first feed sync takes hours. Nothing else waits for it, and the Pono
Score's vulnerability component reads as "not assessed" until it finishes.
