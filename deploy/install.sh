#!/usr/bin/env bash
#
# Kahu installer — Ubuntu 22.04 / 24.04
#
# Two shapes:
#   single       everything on one box (default)
#   distributed  one role per box, 3 or more boxes
#
# The split is by RESOURCE, not by network zone:
#   core     Kahu API + Postgres + Redis        modest CPU, fast disk
#   siem     Wazuh manager + indexer + dashboard RAM-hungry (JVM heap)
#   ai       Ollama                              GPU, or many CPU cores
#   scanner  Greenbone / OpenVAS                 CPU + disk, long feed sync
#
# With exactly three machines, run core, siem and ai; scanner folds into core
# unless you give it a box of its own.
#
#   ./install.sh                                        # all-in-one
#   ./install.sh --mode distributed --role core \
#                --siem-host siem.lan --ai-host gpu.lan
#   ./install.sh --mode distributed --role siem  --core-host core.lan
#   ./install.sh --mode distributed --role ai    --core-host core.lan
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$REPO_ROOT/deploy/compose"
ENV_FILE="$REPO_ROOT/.env"

# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[36m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""
fi

step() { printf '\n%s==>%s %s%s%s\n' "$C_BLUE" "$C_RESET" "$C_BOLD" "$*" "$C_RESET"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '    %s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '\n%serror:%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
# Defaults / arguments
# ─────────────────────────────────────────────────────────────────────────────
MODE=""
ROLE=""
CORE_HOST=""
SIEM_HOST=""
AI_HOST=""
SCANNER_HOST=""
OLLAMA_MODEL="qwen2.5:14b-instruct"
GPU_MODE="auto"            # auto | force | off
ASSUME_YES=0
SKIP_DOCKER=0
SKIP_TUNING=0
SKIP_PULL=0
NO_START=0
JOIN_BUNDLE=""

usage() {
    sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Options:
  --mode single|distributed   Deployment shape (default: single)
  --role core|siem|ai|scanner Role for this machine (distributed only)
  --core-host HOST            Address of the core node (non-core roles)
  --siem-host HOST            Address of the siem node (core role)
  --ai-host HOST              Address of the ai node (core role)
  --scanner-host HOST         Address of the scanner node (core role; optional)
  --join BUNDLE.tar.gz        Join bundle emitted by the core node
  --model NAME                Ollama model (default: qwen2.5:14b-instruct)
  --gpu auto|force|off        NVIDIA GPU for Ollama (default: auto-detect)
  --yes, -y                   Non-interactive; accept defaults
  --skip-docker               Do not install Docker
  --skip-tuning               Do not apply sysctl / THP tuning
  --skip-model-pull           Do not pre-pull the Ollama model
  --no-start                  Configure only; do not start containers
  --help, -h                  This message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)          MODE="${2:-}"; shift 2 ;;
        --role)          ROLE="${2:-}"; shift 2 ;;
        --core-host)     CORE_HOST="${2:-}"; shift 2 ;;
        --siem-host)     SIEM_HOST="${2:-}"; shift 2 ;;
        --ai-host)       AI_HOST="${2:-}"; shift 2 ;;
        --scanner-host)  SCANNER_HOST="${2:-}"; shift 2 ;;
        --join)          JOIN_BUNDLE="${2:-}"; shift 2 ;;
        --model)         OLLAMA_MODEL="${2:-}"; shift 2 ;;
        --gpu)           GPU_MODE="${2:-}"; shift 2 ;;
        -y|--yes)        ASSUME_YES=1; shift ;;
        --skip-docker)   SKIP_DOCKER=1; shift ;;
        --skip-tuning)   SKIP_TUNING=1; shift ;;
        --skip-model-pull) SKIP_PULL=1; shift ;;
        --no-start)      NO_START=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        *)               die "unknown option: $1 (try --help)" ;;
    esac
done

interactive() { [[ $ASSUME_YES -eq 0 && -t 0 ]]; }

ask() {  # ask <prompt> <default>
    local prompt="$1" default="${2:-}" reply
    if ! interactive; then printf '%s' "$default"; return; fi
    read -r -p "    $prompt [${default}]: " reply </dev/tty || reply=""
    printf '%s' "${reply:-$default}"
}

confirm() {  # confirm <prompt>
    local reply
    if ! interactive; then return 0; fi
    read -r -p "    $1 [Y/n]: " reply </dev/tty || reply=""
    [[ -z "$reply" || "$reply" =~ ^[Yy] ]]
}

# ─────────────────────────────────────────────────────────────────────────────
# Preflight
# ─────────────────────────────────────────────────────────────────────────────
TOTAL_RAM_MB=0
CPU_CORES=1
HAS_NVIDIA=0

preflight() {
    step "Preflight"

    [[ $EUID -eq 0 ]] || die "run as root (sudo ./install.sh ...)"

    [[ -r /etc/os-release ]] || die "cannot read /etc/os-release; this installer targets Ubuntu"
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" != "ubuntu" ]]; then
        warn "this installer targets Ubuntu; found ${PRETTY_NAME:-unknown}"
        confirm "Continue anyway?" || die "aborted"
    else
        case "${VERSION_ID:-}" in
            22.04|24.04) ok "Ubuntu ${VERSION_ID}" ;;
            *) warn "untested Ubuntu ${VERSION_ID:-?} (22.04 and 24.04 are tested)" ;;
        esac
    fi

    [[ "$(uname -m)" == "x86_64" ]] || warn "architecture $(uname -m); the Wazuh and Greenbone images are x86_64"

    CPU_CORES="$(nproc)"
    TOTAL_RAM_MB="$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)"
    local disk_gb
    disk_gb="$(df -BG --output=avail "$REPO_ROOT" | tail -1 | tr -dc '0-9')"
    ok "${CPU_CORES} cores, $((TOTAL_RAM_MB / 1024)) GB RAM, ${disk_gb} GB free"

    # Requirements differ sharply by role; only gate on what this box will run.
    local min_ram=4096
    case "$ROLE" in
        siem)  min_ram=8192 ;;
        ai)    min_ram=8192 ;;
        core)  min_ram=4096 ;;
        *)     min_ram=16384 ;;   # single: the whole stack
    esac
    if (( TOTAL_RAM_MB < min_ram )); then
        warn "$((TOTAL_RAM_MB / 1024)) GB RAM is below the $((min_ram / 1024)) GB recommended for this role"
        confirm "Continue anyway?" || die "aborted"
    fi
    if (( disk_gb < 50 )); then
        warn "${disk_gb} GB free; Greenbone feeds and Wazuh indices need well over 50 GB"
        confirm "Continue anyway?" || die "aborted"
    fi

    if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
        HAS_NVIDIA=1
        ok "NVIDIA GPU: $(nvidia-smi -L | head -1)"
    else
        info "no NVIDIA GPU detected — Ollama will run on CPU"
    fi

    for cmd in curl openssl tar; do
        command -v "$cmd" >/dev/null 2>&1 || die "missing required command: $cmd"
    done
}

check_ports() {
    local ports=("$@") busy=()
    command -v ss >/dev/null 2>&1 || return 0
    local listening
    listening="$(ss -lntuH 2>/dev/null | awk '{print $5}' | sed 's/.*://' | sort -u)"
    local p
    for p in "${ports[@]}"; do
        if grep -qx "$p" <<<"$listening"; then busy+=("$p"); fi
    done
    if (( ${#busy[@]} )); then
        warn "ports already in use: ${busy[*]}"
        confirm "Continue anyway?" || die "aborted"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Docker
# ─────────────────────────────────────────────────────────────────────────────
install_docker() {
    step "Docker"
    if (( SKIP_DOCKER )); then info "skipped (--skip-docker)"; return; fi

    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        ok "already present: $(docker --version)"
    else
        info "installing Docker CE from download.docker.com"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq ca-certificates curl gnupg lsb-release

        install -m 0755 -d /etc/apt/keyrings
        if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
                | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            chmod a+r /etc/apt/keyrings/docker.gpg
        fi
        cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable
EOF
        apt-get update -qq
        apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
            docker-buildx-plugin docker-compose-plugin
        systemctl enable --now docker
        ok "installed $(docker --version)"
    fi

    # The GPU reservation is an overlay, so the toolkit is only needed for --gpu.
    if [[ "$(resolve_gpu)" == "on" ]] && ! docker info 2>/dev/null | grep -qi nvidia; then
        info "installing NVIDIA container toolkit"
        curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
            | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
        curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
            | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
            > /etc/apt/sources.list.d/nvidia-container-toolkit.list
        apt-get update -qq
        apt-get install -y -qq nvidia-container-toolkit
        nvidia-ctk runtime configure --runtime=docker
        systemctl restart docker
        ok "NVIDIA container toolkit configured"
    fi
}

resolve_gpu() {
    case "$GPU_MODE" in
        force) echo "on" ;;
        off)   echo "off" ;;
        auto)  if (( HAS_NVIDIA )); then echo "on"; else echo "off"; fi ;;
        *)     die "--gpu must be auto, force or off" ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# Kernel tuning
# ─────────────────────────────────────────────────────────────────────────────
apply_tuning() {
    step "Kernel tuning"
    if (( SKIP_TUNING )); then info "skipped (--skip-tuning)"; return; fi

    # vm.max_map_count only matters where the indexer runs.
    install -m 0644 "$REPO_ROOT/deploy/sysctl.conf" /etc/sysctl.d/99-kahu.conf
    sysctl --system >/dev/null
    ok "sysctl applied (vm.max_map_count=262144)"

    install -m 0644 "$REPO_ROOT/deploy/disable-thp.service" /etc/systemd/system/disable-thp.service
    systemctl daemon-reload
    systemctl enable --now disable-thp >/dev/null 2>&1 || warn "could not enable disable-thp.service"
    ok "transparent huge pages disabled"
}

# ─────────────────────────────────────────────────────────────────────────────
# Secrets and .env
# ─────────────────────────────────────────────────────────────────────────────
gen_secret() { openssl rand -hex 32; }
gen_password() {
    # Wazuh 4.14+ enforces complexity: upper, lower, digit, and special character.
    # Generate a base from random bytes, then guarantee one of each class.
    local base
    base="$(openssl rand -base64 30 | tr -d '/+=' | cut -c1-20)"
    printf 'K!9z%s' "$base" | cut -c1-24
}

# Read an existing value from .env so re-running the installer is not destructive.
existing() {  # existing <KEY>
    [[ -f "$ENV_FILE" ]] || return 0
    sed -n "s/^$1=//p" "$ENV_FILE" | head -1
}

keep_or_new() {  # keep_or_new <KEY> <generator>
    local current; current="$(existing "$1")"
    if [[ -n "$current" ]]; then printf '%s' "$current"; else "$2"; fi
}

# Wazuh indexer heap: half of RAM is the OpenSearch guidance, but this box may be
# running the whole stack. Quarter of RAM, floor 1g, ceiling 31g (compressed oops).
indexer_heap_gb() {
    local gb=$(( TOTAL_RAM_MB / 1024 / 4 ))
    (( gb < 1 )) && gb=1
    (( gb > 31 )) && gb=31
    printf '%d' "$gb"
}

write_env() {
    step "Configuration"

    local secret_key db_password indexer_password wazuh_api_password greenbone_password
    secret_key="$(keep_or_new SECRET_KEY gen_secret)"
    db_password="$(keep_or_new POSTGRES_PASSWORD gen_password)"
    wazuh_api_password="$(keep_or_new WAZUH_API_PASSWORD gen_password)"
    greenbone_password="$(keep_or_new GREENBONE_PASSWORD gen_password)"

    # NOT generated. The indexer's admin credential is a bcrypt hash baked into
    # the image's internal_users.yml; INDEXER_PASSWORD only changes what the
    # manager and dashboard SEND. Generating a random one here would leave them
    # authenticating with a password the indexer has never heard of, and the
    # whole Wazuh stack would come up unhealthy. Changing it for real means
    # mounting a modified internal_users.yml and re-running securityadmin.sh —
    # see deploy/INSTALL.md.
    indexer_password="$(existing WAZUH_INDEXER_PASSWORD)"
    indexer_password="${indexer_password:-admin}"

    # Where each dependency lives, from this node's point of view.
    local pg_host redis_host siem_host ai_host scanner_host
    case "$ROLE" in
        core)    pg_host="postgres"; redis_host="redis"
                 siem_host="${SIEM_HOST}"; ai_host="${AI_HOST}"
                 scanner_host="${SCANNER_HOST:-localhost}" ;;
        siem|ai|scanner)
                 pg_host="${CORE_HOST}"; redis_host="${CORE_HOST}"
                 siem_host="localhost"; ai_host="localhost"; scanner_host="localhost" ;;
        *)       pg_host="postgres"; redis_host="redis"
                 siem_host="wazuh-manager"; ai_host="ollama"; scanner_host="greenbone" ;;
    esac

    local appliance_host
    appliance_host="$(existing APPLIANCE_HOST)"
    if [[ -z "$appliance_host" ]]; then
        appliance_host="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
        appliance_host="${appliance_host:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
        if interactive; then
            appliance_host="$(ask "Address agents should connect to" "${appliance_host:-$(hostname -f)}")"
        fi
    fi

    if [[ -f "$ENV_FILE" ]]; then
        cp -p "$ENV_FILE" "$ENV_FILE.bak.$(date +%Y%m%d%H%M%S)"
        info "existing .env backed up"
    fi

    umask 077
    cat > "$ENV_FILE" <<EOF
# Generated by deploy/install.sh on $(date -Is)
# Role: ${ROLE:-single}   Mode: ${MODE}
# Secrets are generated once and preserved when this installer is re-run.

# ── Core ──
SECRET_KEY=${secret_key}
APPLIANCE_ID=$(existing APPLIANCE_ID || true)
APPLIANCE_HOST=${appliance_host}
LOG_LEVEL=INFO
DEBUG=false
KAHU_CONFIG_DIR=/app/config

# ── Database / cache ──
POSTGRES_USER=kahu
POSTGRES_PASSWORD=${db_password}
POSTGRES_DB=kahu
DATABASE_URL=postgresql+asyncpg://kahu:${db_password}@${pg_host}:5432/kahu
REDIS_URL=redis://${redis_host}:6379/0

# ── Inference ──
OLLAMA_BASE_URL=http://${ai_host}:11434
OLLAMA_MODEL=${OLLAMA_MODEL}

# ── Wazuh ──
WAZUH_API_URL=https://${siem_host}:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=${wazuh_api_password}
WAZUH_INDEXER_URL=https://${siem_host}:9200
WAZUH_INDEXER_USER=admin
# Fixed by the wazuh-indexer image (internal_users.yml). See deploy/INSTALL.md
# before changing this — it is not a Kahu-generated secret.
WAZUH_INDEXER_PASSWORD=${indexer_password}
INDEXER_HEAP=$(indexer_heap_gb)g

# ── Greenbone ──
GREENBONE_URL=http://${scanner_host}:9392
GREENBONE_USER=admin
GREENBONE_PASSWORD=${greenbone_password}

# ── Optional: Cloudflare tunnel (docker compose --profile cloud) ──
TUNNEL_TOKEN=$(existing TUNNEL_TOKEN || true)
EOF
    chmod 600 "$ENV_FILE"
    ok "wrote $ENV_FILE (0600)"
    info "indexer heap: $(indexer_heap_gb)g of $((TOTAL_RAM_MB / 1024)) GB"
}

# ─────────────────────────────────────────────────────────────────────────────
# TLS
# ─────────────────────────────────────────────────────────────────────────────
generate_certs() {
    step "TLS certificates"
    local cert_dir="$REPO_ROOT/config/wazuh/certs"

    if [[ -f "$cert_dir/root-ca.pem" ]]; then
        ok "certificates already present (delete $cert_dir to regenerate)"
        return
    fi

    # In distributed mode the indexer is reached by hostname from other boxes, so
    # its SANs need to cover that name as well as the compose service alias.
    local extra_san=""
    if [[ "$MODE" == "distributed" ]]; then
        local names="${SIEM_HOST}"
        [[ "$ROLE" == "siem" ]] && names="$(hostname -f),$(hostname -I 2>/dev/null | awk '{print $1}')"
        local n
        for n in ${names//,/ }; do
            [[ -z "$n" ]] && continue
            if [[ "$n" =~ ^[0-9.]+$ ]]; then extra_san="${extra_san},IP:${n}"; else extra_san="${extra_san},DNS:${n}"; fi
        done
    fi

    KAHU_EXTRA_SAN="$extra_san" bash "$REPO_ROOT/config/wazuh/generate-certs.sh"
    ok "certificates generated in $cert_dir"
}

# ─────────────────────────────────────────────────────────────────────────────
# Compose assembly
# ─────────────────────────────────────────────────────────────────────────────
COMPOSE_ARGS=()

# Does this node run Ollama at all?
runs_ollama() { [[ "$MODE" == "single" || "$ROLE" == "ai" ]]; }
# Does this node run the Kahu API?
runs_core()   { [[ "$MODE" == "single" || "$ROLE" == "core" ]]; }

build_compose_args() {
    if [[ "$MODE" == "distributed" ]]; then
        # Standalone per-role files rather than overlays of the all-in-one:
        # compose MERGES depends_on rather than removing entries, so overlaying
        # the base would still pull postgres/redis/ollama onto every box.
        local role_file="$COMPOSE_DIR/role-${ROLE}.yml"
        [[ -f "$role_file" ]] || die "no compose file for role '$ROLE' at $role_file"
        COMPOSE_ARGS=(-f "$role_file")
    else
        COMPOSE_ARGS=(-f "$REPO_ROOT/docker-compose.yml")
    fi

    if runs_ollama; then
        if [[ "$(resolve_gpu)" == "on" ]]; then
            COMPOSE_ARGS+=(-f "$COMPOSE_DIR/ollama-gpu.yml")
            info "Ollama: NVIDIA GPU"
        else
            info "Ollama: CPU (no GPU reservation)"
        fi
    fi
}

compose() {
    docker compose --project-directory "$REPO_ROOT" --env-file "$ENV_FILE" \
        "${COMPOSE_ARGS[@]}" "$@"
}

start_stack() {
    step "Starting services"
    if (( NO_START )); then info "skipped (--no-start)"; return; fi

    compose pull --quiet 2>/dev/null || warn "some images could not be pre-pulled; continuing"
    compose up -d
    ok "containers started"

    if (( SKIP_PULL )); then return; fi
    if runs_ollama; then
        step "Ollama model"
        info "pulling ${OLLAMA_MODEL} (several GB; this is the long pole)"
        local i
        for i in $(seq 1 60); do
            if compose exec -T ollama ollama list >/dev/null 2>&1; then break; fi
            sleep 5
        done
        compose exec -T ollama ollama pull "$OLLAMA_MODEL" \
            || warn "model pull failed; run: docker compose exec ollama ollama pull $OLLAMA_MODEL"
    fi
}

health_report() {
    step "Health"
    if (( NO_START )); then info "not started"; return; fi

    if runs_core; then
        local i up=0
        for i in $(seq 1 60); do
            if curl -fsS http://localhost:8000/api/health >/dev/null 2>&1; then up=1; break; fi
            sleep 5
        done
        if (( up )); then ok "Kahu API responding on :8000"
        else warn "Kahu API not responding yet — check: docker compose logs -f core"; fi
    fi
    compose ps --format 'table {{.Service}}\t{{.Status}}' 2>/dev/null || compose ps
}

emit_join_bundle() {
    [[ "$MODE" == "distributed" && "$ROLE" == "core" ]] || return 0
    step "Join bundle"
    local out="$REPO_ROOT/kahu-join-bundle.tar.gz"
    tar -czf "$out" -C "$REPO_ROOT" .env config/wazuh/certs 2>/dev/null || {
        warn "could not build join bundle"; return 0; }
    chmod 600 "$out"
    ok "wrote $out"
    info "copy to each other node, then: sudo ./install.sh --mode distributed --role <role> \\"
    info "        --core-host $(hostname -f) --join kahu-join-bundle.tar.gz"
}

apply_join_bundle() {
    [[ -n "$JOIN_BUNDLE" ]] || return 0
    step "Join bundle"
    [[ -f "$JOIN_BUNDLE" ]] || die "join bundle not found: $JOIN_BUNDLE"
    tar -xzf "$JOIN_BUNDLE" -C "$REPO_ROOT"
    ok "applied shared secrets and certificates from $JOIN_BUNDLE"
}

# ─────────────────────────────────────────────────────────────────────────────
# Interactive mode selection
# ─────────────────────────────────────────────────────────────────────────────
choose_shape() {
    if [[ -z "$MODE" ]]; then
        if interactive; then
            printf '\n%sKahu installer%s\n\n' "$C_BOLD" "$C_RESET"
            printf '  1) Single machine — the whole stack on this box\n'
            printf '  2) Distributed   — one role per box, 3 or more boxes\n\n'
            local choice; choice="$(ask "Choose" "1")"
            case "$choice" in
                1|single) MODE="single" ;;
                2|distributed) MODE="distributed" ;;
                *) die "invalid choice: $choice" ;;
            esac
        else
            MODE="single"
        fi
    fi

    case "$MODE" in
        single)
            [[ -z "$ROLE" ]] || warn "--role is ignored in single mode"
            ROLE=""
            ;;
        distributed)
            if [[ -z "$ROLE" ]] && interactive; then
                printf '\n  core     Kahu API + Postgres + Redis\n'
                printf '  siem     Wazuh manager + indexer + dashboard (needs RAM)\n'
                printf '  ai       Ollama (needs GPU or many cores)\n'
                printf '  scanner  Greenbone (optional 4th box; folds into core otherwise)\n\n'
                ROLE="$(ask "Role for this machine" "core")"
            fi
            case "$ROLE" in
                core)
                    [[ -n "$SIEM_HOST" ]] || SIEM_HOST="$(ask "Address of the siem node" "")"
                    [[ -n "$AI_HOST" ]]   || AI_HOST="$(ask "Address of the ai node" "")"
                    [[ -n "$SIEM_HOST" ]] || die "--siem-host is required for role core"
                    [[ -n "$AI_HOST" ]]   || die "--ai-host is required for role core"
                    ;;
                siem|ai|scanner)
                    [[ -n "$CORE_HOST" ]] || CORE_HOST="$(ask "Address of the core node" "")"
                    [[ -n "$CORE_HOST" ]] || die "--core-host is required for role $ROLE"
                    ;;
                *) die "--role must be core, siem, ai or scanner" ;;
            esac
            ;;
        *) die "--mode must be single or distributed" ;;
    esac
}

summary() {
    local url="http://${1:-localhost}:8000"
    cat <<EOF

${C_GREEN}${C_BOLD}Kahu is installed.${C_RESET}

  Mode        ${MODE}${ROLE:+  (role: ${ROLE})}
  Web UI      ${url}
  Secrets     ${ENV_FILE}  ${C_DIM}(0600 — back this up; losing SECRET_KEY invalidates every token)${C_RESET}

  Logs        docker compose --env-file .env ${COMPOSE_ARGS[*]} logs -f core
  Stop        docker compose --env-file .env ${COMPOSE_ARGS[*]} down
  Restart     docker compose --env-file .env ${COMPOSE_ARGS[*]} up -d

First run: open the web UI and create the initial admin account.
Greenbone's vulnerability feed syncs in the background and takes hours; the rest
of the stack does not wait for it.
EOF
}

# ─────────────────────────────────────────────────────────────────────────────
main() {
    choose_shape
    preflight

    case "${ROLE:-single}" in
        core)    check_ports 8000 5432 6379 ;;
        siem)    check_ports 1514 1515 9200 443 ;;
        ai)      check_ports 11434 ;;
        scanner) check_ports 9392 ;;
        *)       check_ports 8000 11434 9200 9392 443 ;;
    esac

    install_docker
    apply_tuning
    apply_join_bundle
    write_env
    generate_certs
    build_compose_args
    start_stack
    health_report
    emit_join_bundle
    summary "$(existing APPLIANCE_HOST)"
}

main "$@"
