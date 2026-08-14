#!/usr/bin/env bash
#
# Kahu remote-site probe — Ubuntu 22.04 / 24.04
#
# A small VM you drop at a site that has no Kahu appliance of its own. It:
#
#   1. accepts syslog from local network gear on 514/udp and 514/tcp
#      (firewalls, switches, APs, printers, hypervisors — anything that cannot
#      run an agent), and optionally RFC5425 syslog-over-TLS on 6514/tcp
#   2. spools to local disk so a WAN outage queues rather than drops
#   3. ships everything to the Wazuh manager over the agent channel (1514/tcp),
#      which is encrypted and authenticated, instead of firing plaintext syslog
#      across the WAN
#
# Runs on anything that boots Ubuntu: Azure, AWS EC2, VMware, Proxmox, bare
# metal. No Docker — rsyslog and the Wazuh agent are packages, which keeps the
# VM small and lets cloud-init drive the whole thing.
#
#   sudo ./install-probe.sh --manager siem.example.com --site branch-01
#   sudo ./install-probe.sh --manager 10.0.0.10 --site hq --enrollment-password 's3cr3t'
#
set -euo pipefail

MANAGER=""
SITE=""
ENROLLMENT_PASSWORD=""
AGENT_GROUP="probes"
SYSLOG_TLS=0
ALLOW_CIDR=""
SPOOL_MB=2048
WAZUH_VERSION="4.14"
ASSUME_YES=0

if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[36m'
else
    C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi
step() { printf '\n%s==>%s %s%s%s\n' "$C_BLUE" "$C_RESET" "$C_BOLD" "$*" "$C_RESET"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '    %s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '\n%serror:%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Kahu remote-site probe installer

Required:
  --manager HOST              Wazuh manager address (the siem node, or the
                              all-in-one appliance)
  --site NAME                 Site label; becomes the agent name (kahu-probe-NAME)

Optional:
  --enrollment-password PASS  Manager enrolment password, if authd requires one
  --group NAME                Wazuh agent group (default: probes)
  --allow-cidr CIDR           Restrict syslog intake to this network
                              (default: the VM's own subnet)
  --syslog-tls                Also listen on 6514/tcp for syslog over TLS
  --spool-mb MB               Disk spool for WAN outages (default: 2048)
  --wazuh-version VER         Wazuh agent major.minor (default: 4.14)
  --yes, -y                   Non-interactive
  --help, -h                  This message

Ports opened inbound: 514/udp, 514/tcp, and 6514/tcp with --syslog-tls.
Outbound required: 1514/tcp and 1515/tcp to the manager.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --manager)             MANAGER="${2:-}"; shift 2 ;;
        --site)                SITE="${2:-}"; shift 2 ;;
        --enrollment-password) ENROLLMENT_PASSWORD="${2:-}"; shift 2 ;;
        --group)               AGENT_GROUP="${2:-}"; shift 2 ;;
        --allow-cidr)          ALLOW_CIDR="${2:-}"; shift 2 ;;
        --syslog-tls)          SYSLOG_TLS=1; shift ;;
        --spool-mb)            SPOOL_MB="${2:-}"; shift 2 ;;
        --wazuh-version)       WAZUH_VERSION="${2:-}"; shift 2 ;;
        -y|--yes)              ASSUME_YES=1; shift ;;
        -h|--help)             usage; exit 0 ;;
        *)                     die "unknown option: $1 (try --help)" ;;
    esac
done

interactive() { [[ $ASSUME_YES -eq 0 && -t 0 ]]; }
ask() {
    local prompt="$1" default="${2:-}" reply
    if ! interactive; then printf '%s' "$default"; return; fi
    read -r -p "    $prompt [${default}]: " reply </dev/tty || reply=""
    printf '%s' "${reply:-$default}"
}

LOG_DIR="/var/log/kahu-probe"
SPOOL_DIR="/var/spool/rsyslog"

# ─────────────────────────────────────────────────────────────────────────────
preflight() {
    step "Preflight"
    [[ $EUID -eq 0 ]] || die "run as root (sudo ./install-probe.sh ...)"

    [[ -n "$MANAGER" ]] || MANAGER="$(ask "Wazuh manager address" "")"
    [[ -n "$MANAGER" ]] || die "--manager is required"
    [[ -n "$SITE" ]] || SITE="$(ask "Site name" "$(hostname -s)")"
    [[ -n "$SITE" ]] || die "--site is required"
    # Agent names must survive being used as a filename and a Wazuh identifier.
    [[ "$SITE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
        || die "--site must be alphanumeric with . _ - (got '$SITE')"

    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        [[ "${ID:-}" == "ubuntu" ]] || warn "targets Ubuntu; found ${PRETTY_NAME:-unknown}"
    fi

    if [[ -z "$ALLOW_CIDR" ]]; then
        # Default to the VM's own subnet: an open 514 that anything on the
        # internet can reach is a log-injection channel into the SIEM.
        ALLOW_CIDR="$(ip -4 -o route show scope link 2>/dev/null | awk '{print $1}' | head -1)"
        ALLOW_CIDR="${ALLOW_CIDR:-10.0.0.0/8}"
    fi
    ok "manager ${MANAGER}, site ${SITE}, accepting syslog from ${ALLOW_CIDR}"

    # Fail early and clearly rather than after installing packages.
    if command -v nc >/dev/null 2>&1; then
        nc -z -w5 "$MANAGER" 1514 2>/dev/null \
            && ok "manager reachable on 1514/tcp" \
            || warn "cannot reach ${MANAGER}:1514 — check firewall/NSG/security group"
    fi
}

install_packages() {
    step "Packages"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq rsyslog rsyslog-gnutls ca-certificates curl gnupg lsb-release
    ok "rsyslog installed"

    if command -v /var/ossec/bin/wazuh-control >/dev/null 2>&1; then
        ok "Wazuh agent already installed"
        return
    fi
    install -m 0755 -d /usr/share/keyrings
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
    chmod a+r /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/${WAZUH_VERSION}/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
    WAZUH_MANAGER="$MANAGER" apt-get install -y -qq wazuh-agent
    ok "Wazuh agent installed"
}

configure_rsyslog() {
    step "rsyslog"
    install -d -m 0750 "$LOG_DIR"
    install -d -m 0700 "$SPOOL_DIR"

    local tls_block=""
    if (( SYSLOG_TLS )); then
        tls_block=$(cat <<'EOF'

# ── syslog over TLS (RFC5425) ──
# Point $DefaultNetstreamDriverCAFile at your CA and supply a server cert.
global(
  DefaultNetstreamDriver="gtls"
  DefaultNetstreamDriverCAFile="/etc/kahu-probe/tls/ca.pem"
  DefaultNetstreamDriverCertFile="/etc/kahu-probe/tls/probe.pem"
  DefaultNetstreamDriverKeyFile="/etc/kahu-probe/tls/probe-key.pem"
)
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1" StreamDriver.AuthMode="anon")
input(type="imtcp" port="6514")
EOF
        )
        install -d -m 0700 /etc/kahu-probe/tls
        info "TLS listener enabled — place ca.pem, probe.pem and probe-key.pem in /etc/kahu-probe/tls"
    fi

    cat > /etc/rsyslog.d/10-kahu-probe.conf <<EOF
# Managed by deploy/install-probe.sh — edits are overwritten on re-run.
#
# Collects syslog from local network devices and writes one file per source
# host. The Wazuh agent tails these files and ships them to the manager over the
# encrypted agent channel, so nothing crosses the WAN in plaintext.

module(load="imudp")
input(type="imudp" port="514")

module(load="imtcp")
input(type="imtcp" port="514")
${tls_block}

# Only accept from the site network. Without this the probe will happily relay
# anything that reaches it, which is a log-injection path into the SIEM.
\$AllowedSender UDP, ${ALLOW_CIDR}
\$AllowedSender TCP, ${ALLOW_CIDR}

# Spool to disk when the agent or the WAN is unavailable.
\$WorkDirectory ${SPOOL_DIR}
\$ActionQueueType LinkedList
\$ActionQueueFileName kahu_probe
\$ActionQueueMaxDiskSpace ${SPOOL_MB}m
\$ActionQueueSaveOnShutdown on
\$ActionResumeRetryCount -1

template(name="KahuPerHost" type="string" string="${LOG_DIR}/%HOSTNAME:::secpath-replace%.log")

if (\$inputname == "imudp" or \$inputname == "imtcp") then {
    action(type="omfile" dynaFile="KahuPerHost" fileCreateMode="0640" dirCreateMode="0750")
    stop
}
EOF

    cat > /etc/logrotate.d/kahu-probe <<EOF
${LOG_DIR}/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 syslog adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || true
    endscript
}
EOF

    rsyslogd -N1 >/dev/null 2>&1 || die "rsyslog configuration failed validation (rsyslogd -N1)"
    systemctl restart rsyslog
    ok "listening on 514/udp and 514/tcp, spooling up to ${SPOOL_MB} MB"
}

configure_agent() {
    step "Wazuh agent"
    local conf=/var/ossec/etc/ossec.conf
    [[ -f "$conf" ]] || die "$conf not found; agent install failed"
    cp -p "$conf" "${conf}.bak.$(date +%Y%m%d%H%M%S)"

    # Tail everything rsyslog writes. wildcard needs Wazuh >= 4.3.
    if ! grep -q "kahu-probe" "$conf"; then
        python3 - "$conf" "$LOG_DIR" <<'PY'
import sys, re
conf_path, log_dir = sys.argv[1], sys.argv[2]
block = f"""
  <localfile>
    <log_format>syslog</log_format>
    <location>{log_dir}/*.log</location>
  </localfile>
"""
src = open(conf_path, encoding="utf-8", errors="surrogateescape").read()
# Insert before the final </ossec_config> so we do not disturb existing blocks.
idx = src.rfind("</ossec_config>")
if idx == -1:
    sys.exit("no </ossec_config> in ossec.conf")
open(conf_path, "w", encoding="utf-8", errors="surrogateescape").write(
    src[:idx] + block + src[idx:]
)
PY
        ok "agent will tail ${LOG_DIR}/*.log"
    else
        ok "agent already configured for ${LOG_DIR}"
    fi

    local agent_name="kahu-probe-${SITE}"
    if [[ -f /var/ossec/etc/client.keys && -s /var/ossec/etc/client.keys ]]; then
        ok "already enrolled as $(cut -d' ' -f2 /var/ossec/etc/client.keys | head -1)"
    else
        info "enrolling as ${agent_name}"
        local args=(-m "$MANAGER" -A "$agent_name" -G "$AGENT_GROUP")
        [[ -n "$ENROLLMENT_PASSWORD" ]] && args+=(-P "$ENROLLMENT_PASSWORD")
        if /var/ossec/bin/agent-auth "${args[@]}"; then
            ok "enrolled"
        else
            warn "enrolment failed — check that authd is listening on ${MANAGER}:1515"
            warn "re-run: /var/ossec/bin/agent-auth -m ${MANAGER} -A ${agent_name} -G ${AGENT_GROUP}"
        fi
    fi

    systemctl daemon-reload
    systemctl enable wazuh-agent >/dev/null 2>&1 || true
    systemctl restart wazuh-agent
    ok "agent running"
}

configure_firewall() {
    step "Firewall"
    if ! command -v ufw >/dev/null 2>&1 || ! ufw status >/dev/null 2>&1; then
        info "ufw not active; skipping (open 514/udp and 514/tcp yourself)"
        return
    fi
    ufw allow from "$ALLOW_CIDR" to any port 514 proto udp >/dev/null
    ufw allow from "$ALLOW_CIDR" to any port 514 proto tcp >/dev/null
    (( SYSLOG_TLS )) && ufw allow from "$ALLOW_CIDR" to any port 6514 proto tcp >/dev/null
    ok "ufw rules added for ${ALLOW_CIDR}"
    info "cloud VMs also need the port opened in the Azure NSG / AWS security group"
}

summary() {
    cat <<EOF

${C_GREEN}${C_BOLD}Probe installed.${C_RESET}

  Site        ${SITE}   (agent: kahu-probe-${SITE}, group: ${AGENT_GROUP})
  Manager     ${MANAGER}
  Listening   514/udp, 514/tcp$( (( SYSLOG_TLS )) && printf ', 6514/tcp (TLS)' )
  Accepting   ${ALLOW_CIDR}
  Log files   ${LOG_DIR}/<sourcehost>.log
  Spool       ${SPOOL_DIR} (up to ${SPOOL_MB} MB while the WAN is down)

Point your network devices' syslog at this VM's address on port 514.

  Agent state     /var/ossec/bin/wazuh-control status
  Agent log       tail -f /var/ossec/logs/ossec.log
  Arriving logs   ls -la ${LOG_DIR}
  Test injection  logger -n 127.0.0.1 -P 514 -d "kahu probe test"

Confirm on the appliance that the agent shows Active, then check the Kahu feed.
EOF
}

main() {
    preflight
    install_packages
    configure_rsyslog
    configure_agent
    configure_firewall
    summary
}

main "$@"
