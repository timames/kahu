#!/bin/bash
# Generate self-signed TLS certificates for Wazuh components.
# Run once before first docker compose up.

set -euo pipefail

# Disable MSYS path conversion (Git Bash on Windows)
export MSYS_NO_PATHCONV=1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"
mkdir -p "$CERT_DIR"

DAYS=3650
SUBJ_BASE="/C=US/ST=Hawaii/O=ComplyHI/OU=Kuahene"

echo "==> Generating root CA..."
openssl genrsa -out "$CERT_DIR/root-ca-key.pem" 2048
openssl req -new -x509 -sha256 -key "$CERT_DIR/root-ca-key.pem" \
  -out "$CERT_DIR/root-ca.pem" -days $DAYS \
  -subj "$SUBJ_BASE/CN=Kuahene Root CA"

generate_cert() {
  local name="$1"
  local cn="$2"
  local san="$3"

  echo "==> Generating cert for $name ($cn)..."
  openssl genrsa -out "$CERT_DIR/$name-key.pem" 2048

  openssl req -new -sha256 -key "$CERT_DIR/$name-key.pem" \
    -out "$CERT_DIR/$name.csr" \
    -subj "$SUBJ_BASE/CN=$cn"

  # Create SAN extension config
  cat > "$CERT_DIR/$name-ext.cnf" <<EOF
[v3_req]
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment
subjectAltName=$san
EOF

  openssl x509 -req -sha256 -in "$CERT_DIR/$name.csr" \
    -CA "$CERT_DIR/root-ca.pem" -CAkey "$CERT_DIR/root-ca-key.pem" \
    -CAcreateserial -out "$CERT_DIR/$name.pem" -days $DAYS \
    -extfile "$CERT_DIR/$name-ext.cnf" -extensions v3_req

  rm -f "$CERT_DIR/$name.csr" "$CERT_DIR/$name-ext.cnf"
}

# Indexer
generate_cert "indexer" "wazuh-indexer" "DNS:wazuh-indexer,DNS:localhost,IP:127.0.0.1"

# Manager (filebeat certs)
generate_cert "filebeat" "wazuh-manager" "DNS:wazuh-manager,DNS:localhost,IP:127.0.0.1"

# Dashboard
generate_cert "dashboard" "wazuh-dashboard" "DNS:wazuh-dashboard,DNS:localhost,IP:127.0.0.1"

# Admin cert (for security plugin initialization)
generate_cert "admin" "admin" "DNS:localhost,IP:127.0.0.1"

# Set permissions
chmod 644 "$CERT_DIR"/*.pem
chmod 600 "$CERT_DIR"/*-key.pem

echo ""
echo "==> Certificates generated in $CERT_DIR"
ls -la "$CERT_DIR"
