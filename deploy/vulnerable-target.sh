#!/usr/bin/env bash
set -euo pipefail

# Deliberately vulnerable CX22 setup for Greenbone scan targets.
# Run on ONE of the three CX22s. The other two stay hardened.
#
# This creates real criticals/highs in Greenbone reports so the
# Pono Score moves visibly when you remediate live.
#
# WARNING: Only expose to your own scanner. Do not put this on the public internet
# without firewall rules restricting source IPs.

SCANNER_IP="${1:?Usage: $0 <scanner-ip>}"

echo "=== Kahu Vulnerable Target Setup ==="
echo "Scanner IP: $SCANNER_IP"

# ── 1. Install intentionally outdated/weak services ──
apt-get update
apt-get install -y vsftpd openssh-server nginx-light docker.io ufw

# ── 2. SSH: enable weak ciphers and password auth ──
cat > /etc/ssh/sshd_config.d/99-weak.conf <<'SSHEOF'
PasswordAuthentication yes
PermitRootLogin yes
Ciphers aes128-cbc,aes256-cbc,3des-cbc,aes128-ctr,aes256-ctr
MACs hmac-sha1,hmac-md5,hmac-sha2-256
KexAlgorithms diffie-hellman-group14-sha1,diffie-hellman-group1-sha1,ecdh-sha2-nistp256
SSHEOF
systemctl restart sshd

# ── 3. Anonymous FTP ──
cat > /etc/vsftpd.conf <<'FTPEOF'
listen=YES
anonymous_enable=YES
local_enable=NO
write_enable=NO
anon_root=/srv/ftp
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
FTPEOF
mkdir -p /srv/ftp
echo "nothing sensitive here" > /srv/ftp/readme.txt
systemctl enable --now vsftpd

# ── 4. Exposed Redis (no auth, bound to all interfaces) ──
docker run -d --name vuln-redis --restart unless-stopped -p 6379:6379 redis:6 redis-server --protected-mode no

# ── 5. DVWA (web vulns) ──
docker run -d --name dvwa --restart unless-stopped -p 8080:80 ghcr.io/digininja/dvwa:latest

# ── 6. Outdated nginx with server tokens ──
cat > /etc/nginx/sites-available/default <<'NGXEOF'
server {
    listen 80 default_server;
    server_tokens on;
    root /var/www/html;
    index index.html;
    location / {
        try_files $uri $uri/ =404;
    }
}
NGXEOF
echo "<h1>Test server</h1>" > /var/www/html/index.html
systemctl enable --now nginx

# ── 7. Firewall: only allow scanner + SSH from anywhere ──
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow from "$SCANNER_IP" to any
ufw --force enable

echo ""
echo "=== Vulnerable target ready ==="
echo "Services exposed:"
echo "  22/tcp   - SSH (weak ciphers)"
echo "  21/tcp   - FTP (anonymous)"
echo "  80/tcp   - nginx (server tokens on)"
echo "  6379/tcp - Redis (no auth)"
echo "  8080/tcp - DVWA"
echo ""
echo "Firewall allows full access from $SCANNER_IP only."
echo "SSH remains open from all IPs for management."
