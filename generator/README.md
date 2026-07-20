# Kuahene Demo Stack

A cloud-hosted traffic generator that makes a Kuahene appliance look like it is
watching a real 60-person engineering firm — plus nine scenarios you can fire
from your phone mid-presentation.

Two things it produces:

- **Baseline noise** — a diurnal curve of ordinary activity (logons, SMB
  traffic, web browsing, print jobs, AP associations, SNMP link events) that
  ramps at 6am Honolulu time, peaks mid-morning, dips at lunch, and goes quiet
  overnight. Weekends are quiet too. An appliance sitting at zero is a dead
  demo; this fixes that.
- **Scenarios on demand** — port scan, VPN password spray, impossible travel,
  lateral movement, privilege escalation with log wipe, C2 beaconing, data
  exfiltration, ransomware detonation, and an infrastructure fault. Fire one
  and narrate while the dashboard reacts.

Everything is *synthetic log records describing activity*. The generator does
not scan, authenticate against, or touch any real system. The only exception is
the optional M365 module, which performs legitimate admin actions in your own
developer tenant.

---

## ⚠️ Read this before you deploy

The Kuahene architecture says the appliance **never accepts inbound WAN
connections**. A cloud generator sending syslog to a public IP would violate
that on your own demo box, and worse, would leave 514/udp open to the internet
for anyone to spray. Don't.

**Use a WireGuard tunnel.** The generator VPS and the demo appliance both join a
small private network; `TARGET_HOST` is the appliance's tunnel address
(e.g. `10.77.0.2`). The appliance still accepts nothing from the public
internet, and the demo stays honest to the architecture you're selling.

Alternative: run the demo appliance *in the same cloud VPC* as the generator and
keep both off the public internet entirely. Best option if you're demoing
remotely and don't want hardware in the loop at all.

See `ops/README.md` for the WireGuard setup.

---

## Deploy

Any 2 vCPU / 4 GB VPS will do — the generator is I/O bound and idles near zero.

```bash
git clone <your-repo> kuahene-demo && cd kuahene-demo
cp .env.example .env
openssl rand -hex 24        # paste into API_TOKEN
vim .env                    # set TARGET_HOST and API_TOKEN
vim ops/Caddyfile           # set your hostname
docker compose up -d --build
```

Then open `https://your-host/` and paste the token. Add it to your phone's home
screen — it's built for a 380px viewport because you'll be holding it while
talking.

**Verify before pointing it at anything real:** set `DRY_RUN=true` and watch
`docker compose logs -f generator`. Every event prints instead of being sent.

---

## Control

The panel is the easy path, but everything is REST if you'd rather script it:

```bash
T=your-token-here
H="X-Demo-Token: $T"
curl -s -H "$H" https://your-host/api/status | jq
curl -s -H "$H" https://your-host/api/scenarios | jq
curl -s -XPOST -H "$H" https://your-host/api/scenarios/ransomware/fire
curl -s -XPOST -H "$H" https://your-host/api/baseline/stop
```

`INTENSITY` scales baseline volume. 1.0 is a quiet 60-person office (~6 events/s
at peak). Push to 3.0 if you want the appliance to look busy; drop to 0.3 if
you're demoing on constrained hardware.

---

## Suggested demo arc

1. **Open on the dashboard with baseline running.** Let them see a normal day.
   "This is Tuesday. Nothing is wrong. That's the point — you're seeing what
   normal looks like, which is the only way to know when it isn't."
2. **Fire `port_scan`.** Fast, obvious, ten seconds. Warms up the room.
3. **Fire `brute_force`.** Runs ~45 seconds and ends with one login *succeeding*.
   Stop talking when that line lands.
4. **Fire `device_failure`.** Reframes the product: not every alert is an
   attacker, and the box earns its keep on Tuesdays too.
5. **Fire `ransomware`.** The closer. Shadow copies deleted, AV quarantine
   fails, mass renames on the file server.
6. **Show the compliance tab.** The evidence for everything they just watched is
   already filed against their controls. Nobody typed anything.

Run `c2_beacon` in the background during the first few minutes if you want
something for the AI triage to have already correlated by the time you get to it.

---

## M365 / Entra events

`m365/m365_events.py` generates **real** audit and sign-in events in a Microsoft
365 Developer tenant you control (free, 25 seats). Real Graph API data means the
M365 connector demo isn't faked.

Setup: register an app in your dev tenant, grant application permissions
(`User.ReadWrite.All`, `Directory.ReadWrite.All`, `AuditLog.Read.All`,
`Group.ReadWrite.All`), admin-consent them, then:

```bash
export M365_TENANT_ID=... M365_CLIENT_ID=... M365_CLIENT_SECRET=...
python m365/m365_events.py baseline        # directory churn
python m365/m365_events.py failed_logins   # 12 real failed sign-ins
python m365/m365_events.py privilege       # role assign + remove
python m365/m365_events.py oversharing     # anonymous sharing link
python m365/m365_events.py cleanup         # delete everything it made
```

Every object it creates is prefixed `kuahene-demo-`, so `cleanup` is
unambiguous. Run it after every demo.

**The free geography trick:** your generator VPS is not in Hawaii. Sign into the
dev tenant from the VPS while you're sitting in Honolulu, and Entra records a
genuine impossible-travel pattern — real risk detection, real Graph data, no
fakery. Pick a VPS region far from you (Frankfurt, Singapore) to make the
geography obvious.

Note that Entra sign-in logs lag a few minutes. Fire `failed_logins` before you
start presenting, not during.

---

## Layout

```
generator/app/
  config.py      env-driven configuration
  topology.py    the synthetic org — 71 hosts, 60 users, stable across feeds
  emitters.py    syslog (RFC3164/5424), NetFlow v5, SNMP v2c traps
  scenarios.py   baseline profile + the nine scenarios
  engine.py      baseline loop, scenario playback, status
  main.py        REST API + phone control panel
m365/            real-tenant event generation
ops/             Caddyfile, WireGuard notes
```

Adding a scenario: write a generator function yielding `(delay, callable)` and
register it in `SCENARIOS`. The control panel picks it up automatically.

---

## Cautions

- The generator's control API is protected by one shared token over TLS. That is
  adequate for a demo box and inadequate for anything else. Don't reuse the
  token, and take the VPS down between demo cycles.
- Hostile IPs in scenarios use TEST-NET-3 (`203.0.113.0/24`, RFC 5737) —
  reserved for documentation, never routable to a real host. Don't swap in real
  IPs to make it look better; you'd be generating logs that accuse a real
  network of things it didn't do.
- The synthetic org is fictional (`kaipacific.example`, RFC 2606). Keep it that
  way, and never point this at a customer's production appliance — synthetic
  events would land in the same evidence store that's supposed to be
  assessor-grade.
