# Demo network — WireGuard

The generator must reach the appliance's collector ports (514/udp, 162/udp,
2055/udp) without those ports being exposed to the internet. WireGuard gives you
that in about ten minutes and keeps the demo consistent with the architecture
you're selling.

```
  ┌──────────────────┐        WireGuard         ┌──────────────────┐
  │  Generator VPS   │  10.77.0.1 ── 10.77.0.2  │  Demo appliance  │
  │  (Frankfurt/SG)  │◄────────────────────────►│  (lab or cloud)  │
  └──────────────────┘   udp/51820 only          └──────────────────┘
         │                                              ▲
         └── 443 (Caddy, control panel) ────────────────┘
```

## Generator VPS (`10.77.0.1`)

```bash
apt update && apt install -y wireguard
wg genkey | tee /etc/wireguard/priv | wg pubkey > /etc/wireguard/pub
cat >/etc/wireguard/wg0.conf <<'EOF'
[Interface]
Address = 10.77.0.1/24
PrivateKey = <generator private key>
ListenPort = 51820

[Peer]
# appliance
PublicKey = <appliance public key>
AllowedIPs = 10.77.0.2/32
EOF
systemctl enable --now wg-quick@wg0
```

## Appliance (`10.77.0.2`)

```bash
[Interface]
Address = 10.77.0.2/24
PrivateKey = <appliance private key>

[Peer]
PublicKey = <generator public key>
Endpoint = <vps-public-ip>:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```

The appliance dials out; nothing inbound from the public internet is required.
Set `TARGET_HOST=10.77.0.2` in `.env`.

## Firewall on the VPS

Only two ports need to be reachable from the internet:

```bash
ufw default deny incoming
ufw allow 22/tcp        # your management access — restrict by source if you can
ufw allow 443/tcp       # control panel
ufw allow 51820/udp     # wireguard
ufw enable
```

Collector traffic never leaves the tunnel, so 514/162/2055 stay closed
everywhere.

## Verify

From the VPS, once the tunnel is up:

```bash
wg show                                   # handshake present?
ping -c3 10.77.0.2
nc -zvu 10.77.0.2 514                     # syslog reachable
docker compose logs -f generator          # errors counter should stay at 0
```

The control panel's status line shows a live `errors` count. If it climbs, the
appliance isn't receiving — check the tunnel before you blame the generator.
