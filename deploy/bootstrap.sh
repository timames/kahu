#!/usr/bin/env bash
set -euo pipefail

# Kahu demo server bootstrap
# Assumes: Debian 13, RAID1 already configured via installimage

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Kahu Demo Server Bootstrap ==="

# ── 1. System packages ──
apt-get update
apt-get install -y ca-certificates curl gnupg lsb-release

# ── 2. Docker CE ──
if ! command -v docker &>/dev/null; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/debian $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
    echo "Docker installed."
else
    echo "Docker already installed, skipping."
fi

# ── 3. Kernel tuning ──
cp "$SCRIPT_DIR/sysctl.conf" /etc/sysctl.d/99-kahu.conf
sysctl --system

cp "$SCRIPT_DIR/disable-thp.service" /etc/systemd/system/disable-thp.service
systemctl daemon-reload
systemctl enable --now disable-thp

echo "Kernel tuning applied."

# ── 4. Create data directories ──
mkdir -p /opt/kahu/{greenbone,wazuh,misp,shuffle,iris,netbox,ciso-assistant,keycloak,vault,grafana}

# ── 5. Start Greenbone first (feed sync is the long pole) ──
echo "=== Starting Greenbone (feed sync will take hours) ==="
docker compose -f "$SCRIPT_DIR/docker-compose.demo.yml" up -d greenbone-vulnerability-manager greenbone-pg-gvm greenbone-redis greenbone-ospd-openvas greenbone-gsa greenbone-notus-scanner

echo ""
echo "Greenbone is syncing feeds. Monitor with:"
echo "  docker compose -f $SCRIPT_DIR/docker-compose.demo.yml logs -f greenbone-vulnerability-manager"
echo ""
echo "When feeds are imported, bring up the rest:"
echo "  docker compose -f $SCRIPT_DIR/docker-compose.demo.yml up -d"
echo ""
echo "Bootstrap complete."
